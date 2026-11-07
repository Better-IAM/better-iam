package server

// Port of packages/server/src/api/compliance.ts. The compliance center: turn the built-in checks into controls (by
// adopting SOC 2, ISO 27001, NIST 800-53 or GDPR mappings, or one by one), evaluate them (the scheduler job
// `iam.compliance.evaluateAll`, or `evaluate`), grant time-boxed exceptions for accepted findings (a second person
// approves each), see each framework requirement's status, and export signed evidence. Reading needs
// `iam:compliance:read`, running evaluations `iam:compliance:evaluate`, the rest `iam:compliance:manage`. Findings name
// people only for callers who may read the directory (`iam:identities:read`).

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ComplianceAPI is the `compliance` API group (packages/server/src/api/compliance.ts createComplianceApi): every method runs through the
// operation envelope; the router maps POST {basePath}/compliance/{method} onto it.
type ComplianceAPI struct {
	server *ServerContext
}

// CreateComplianceAPI builds the `compliance` API group.
func CreateComplianceAPI(server *ServerContext) *ComplianceAPI {
	return &ComplianceAPI{server: server}
}

const (
	maxComplianceControls = 200
	resultRetentionMs     = 400 * 86_400_000.0
	staleAfterMs          = 3 * 86_400_000.0
	// manualIntervalMs: manual evaluations per tenant run at most one a minute (the scheduled job is not limited).
	manualIntervalMs = 60_000.0
)

// evidenceKeyEntry is an Ed25519 evidence key and its public JWK.
type evidenceKeyEntry struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	jwk        *core.Object
	kid        string
}

// evidenceKeyCache holds the keys derived per deployment secret.
var evidenceKeyCache sync.Map

// evidenceKey is the Ed25519 key derived from the deployment secret, so every instance signs alike and rotation keeps
// old packs valid.
func evidenceKey(secret string) *evidenceKeyEntry {
	if cached, ok := evidenceKeyCache.Load(secret); ok {
		return cached.(*evidenceKeyEntry)
	}
	seed := sha256.Sum256(utf8Bytes("better-iam:compliance-evidence:ed25519:" + secret))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	x := base64url(publicKey)
	// RFC 7638 thumbprint: the required members in lexicographic order.
	thumbprint := sha256.Sum256(utf8Bytes(core.CanonicalJSON(core.NewObject("crv", "Ed25519", "kty", "OKP", "x", x))))
	kid := base64url(thumbprint[:])
	entry := &evidenceKeyEntry{
		privateKey: privateKey,
		publicKey:  publicKey,
		jwk:        core.NewObject("kty", "OKP", "crv", "Ed25519", "x", x, "kid", kid, "alg", "EdDSA", "use", "sig"),
		kid:        kid,
	}
	evidenceKeyCache.Store(secret, entry)
	return entry
}

// evidencePackDigest is SHA-256 (base64url) of the canonical JSON of a pack's body.
func evidencePackDigest(body any) string {
	sum := sha256.Sum256(utf8Bytes(core.CanonicalJSON(body)))
	return base64url(sum[:])
}

// evidenceLegacySignature is the version 1 signature (HMAC-SHA256 under the deployment secret); those packs still verify on
// the deployment that made them.
func evidenceLegacySignature(secret string, body any) string {
	key := sha256.Sum256(utf8Bytes("better-iam:compliance-evidence:" + secret))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(utf8Bytes(core.CanonicalJSON(body)))
	return base64url(mac.Sum(nil))
}

// verifyEd25519JWK verifies an Ed25519 signature with a JWK's `x`; a key that cannot be imported fails.
func verifyEd25519JWK(x any, message string, signature string) bool {
	text, ok := x.(string)
	if !ok {
		return false
	}
	public := nodeBase64Decode(text)
	if len(public) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), utf8Bytes(message), nodeBase64Decode(signature))
}

// VerifyEvidencePack (api/compliance.ts verifyEvidencePack) verifies an evidence pack offline, with the deployment's
// published evidence keys (`compliance.evidenceKeys`, as a list or a JWKS): the digest must match the pack's content
// and the signature must verify with the key it names. Needs no server.
func VerifyEvidencePack(pack any, keys any) *core.Object {
	if !truthy(pack) || (typeOf(pack) != "object") {
		return core.NewObject("valid", false, "reason", "not a pack")
	}
	record, isObject := pack.(*core.Object)
	var digest, signature any = core.Undefined, core.Undefined
	body := core.NewObject()
	if isObject {
		digest, signature = record.Get("digest"), record.Get("signature")
		body = record.Clone()
		body.Delete("digest")
		body.Delete("signature")
	}
	digestText, digestOK := digest.(string)
	if !digestOK || !truthy(signature) || typeOf(signature) != "object" {
		return core.NewObject("valid", false, "reason", "unsigned")
	}
	value, valueOK := member(signature, "value").(string)
	if !valueOK {
		return core.NewObject("valid", false, "reason", "unsigned")
	}
	if evidencePackDigest(body) != digestText {
		return core.NewObject("valid", false, "reason", "digest mismatch")
	}
	var list []any
	if items, ok := keys.([]any); ok {
		list = items
	} else {
		list, _ = member(keys, "keys").([]any)
	}
	var key any
	for _, item := range list {
		if strictEquals(member(item, "kid"), member(signature, "kid")) {
			key = item
			break
		}
	}
	if key == nil {
		return core.NewObject("valid", false, "reason", "unknown key")
	}
	if verifyEd25519JWK(member(key, "x"), digestText, value) {
		return core.NewObject("valid", true, "kid", member(key, "kid"))
	}
	return core.NewObject("valid", false, "reason", "bad signature")
}

var controlKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// complianceControlKey is controlKey.
func complianceControlKey(value any) (string, error) {
	key, err := Text(value, "key", 64)
	if err != nil {
		return "", err
	}
	if !controlKeyPattern.MatchString(key) {
		return "", invalidInput("Control keys use lowercase letters, digits, dots, underscores or hyphens")
	}
	return key, nil
}

// complianceMappings is mappings: distinct trimmed references, sorted (at most 50).
func complianceMappings(value any) ([]any, error) {
	if isUndefined(value) {
		return []any{}, nil
	}
	items, err := Strings(value, "mappings")
	if err != nil {
		return nil, err
	}
	var list []string
	for _, item := range items {
		text, err := Text(item, "mappings", 64)
		if err != nil {
			return nil, err
		}
		list = append(list, core.JSTrim(text))
	}
	list = unique(list)
	if len(list) > 50 {
		return nil, invalidInput("At most 50 mappings")
	}
	sortStrings(list)
	return stringsOf(list), nil
}

// complianceEmptyCounts is a run's counts per status.
func complianceEmptyCounts() *core.Object {
	return core.NewObject("pass", 0.0, "fail", 0.0, "warn", 0.0, "not-applicable", 0.0)
}

// requirementSeverity orders statuses worst first: a requirement is as good as its worst control.
var requirementSeverity = map[string]int{
	"fail":           6,
	"disabled":       5,
	"not-evaluated":  4,
	"no-control":     3,
	"warn":           2,
	"pass":           1,
	"not-applicable": 0,
}

// namesIdentity is whether a finding names this person (an exception for it would be their own).
func namesIdentity(subject string, identityID any) bool {
	id := jsString(identityID)
	return subject == "identity:"+id || strings.HasPrefix(subject, "identity:"+id+":")
}

// complianceExceptionStatus is `exception.status ?? 'approved'`.
func complianceExceptionStatus(exception *core.Object) any {
	return coalesce(exception.Get("status"), "approved")
}

// complianceSortBy is `(a, b) => (a[key] < b[key] ? -1 : 1)` as a stable sort.
func complianceSortBy(records []*core.Object, key string) {
	sort.SliceStable(records, func(i, j int) bool {
		return compareUTF16(jsString(records[i].Get(key)), jsString(records[j].Get(key))) < 0
	})
}

// complianceSlice is String.prototype.slice(0, end) over UTF-16 units.
func complianceSlice(text string, end int) string {
	units := core.ToUTF16(text)
	if len(units) <= end {
		return text
	}
	return core.FromUTF16(units[:end])
}

// evaluatedControl is a control and the result its check produced.
type evaluatedControl struct {
	control *core.Object
	result  *core.Object
}

// runComplianceEvaluation runs a tenant's enabled controls (or the named ones, keys nil for all) and records the results,
// a run, and an audit event. The checks read outside any transaction; only the results are written, in one short
// transaction. minIntervalMs 0 sets no limit.
func runComplianceEvaluation(ctx context.Context, server *ServerContext, tenantID string, triggeredBy any, keys []string, minIntervalMs float64) (run *core.Object, results []*core.Object, err error) {
	store := server.Store
	tenant, err := server.Tenant(ctx, store, tenantID)
	if err != nil {
		return nil, nil, err
	}
	now := float64(server.Now())
	if minIntervalMs != 0 {
		runs, err := store.Find(ctx, "complianceRuns", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, nil, err
		}
		last := 0.0
		for _, run := range runs {
			last = complianceMax(last, jsNumber(run.Get("evaluatedAt")))
		}
		if last > now-minIntervalMs {
			return nil, nil, core.NewIamError("RATE_LIMITED", "The controls were evaluated less than a minute ago", 429)
		}
	}
	found, err := store.Find(ctx, "complianceControls", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	var controls []*core.Object
	for _, control := range found {
		if truthy(control.Get("enabled")) && (keys == nil || containsString(keys, jsString(control.Get("key"))) && complianceIsString(control.Get("key"))) {
			controls = append(controls, control)
		}
	}
	complianceSortBy(controls, "key")
	allExceptions, err := store.Find(ctx, "complianceExceptions", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	var exceptions []*core.Object
	for _, exception := range allExceptions {
		if exceptionActive(exception, now) {
			exceptions = append(exceptions, exception)
		}
	}
	runID := ID()
	var evaluated []evaluatedControl
	var checkpoint *core.Object
	for _, control := range controls {
		check, ok := control.Get("checkId").(string)
		if !ok {
			continue
		}
		definition := CheckByID[check]
		if definition == nil {
			continue
		}
		excepted := map[string]bool{}
		if !definition.noExceptions() {
			for _, item := range exceptions {
				if item.Get("controlKey") == control.Get("key") {
					excepted[jsString(item.Get("subject"))] = true
				}
			}
		}
		var status, rawStatus, summary any
		metrics := core.NewObject()
		findings := []*core.Object{}
		outcome, failure := runComplianceCheck(ctx, server, store, definition, tenant, control, now)
		if failure == nil {
			metrics = outcome.Metrics
			findings = make([]*core.Object, len(outcome.Findings))
			var uncovered []*core.Object
			for index, finding := range outcome.Findings {
				if excepted[findingSubject(finding)] {
					findings[index] = finding.Spread(core.NewObject("excepted", true))
				} else {
					findings[index] = finding
					uncovered = append(uncovered, finding)
				}
			}
			rawStatus = outcome.judge(outcome.Findings).Get("status")
			verdict := outcome.judge(uncovered)
			status, summary = verdict.Get("status"), verdict.Get("summary")
			if outcome.Checkpoint != nil {
				checkpoint = outcome.Checkpoint
			}
		} else {
			if known, ok := asIamError(failure); ok && known.Code == "NOT_IMPLEMENTED" {
				// Another unit's stub: surface it rather than recording a failure the TypeScript server would not.
				return nil, nil, failure
			}
			// A check that cannot run fails, visibly, rather than passing by omission.
			status, rawStatus = "fail", "fail"
			summary = complianceSlice("The check could not run: "+errorMessage(failure), 300)
		}
		exceptedCount := 0.0
		for _, finding := range findings {
			if truthy(finding.Get("excepted")) {
				exceptedCount++
			}
		}
		shown := findings
		if len(shown) > 200 {
			shown = shown[:200]
		}
		evaluated = append(evaluated, evaluatedControl{control: control, result: core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"runId", runID,
			"controlId", control.Get("id"),
			"controlKey", control.Get("key"),
			"checkId", control.Get("checkId"),
			"status", status,
			"rawStatus", rawStatus,
			"summary", summary,
			"metrics", metrics,
			"findings", objectList(shown),
			"findingsTotal", float64(len(findings)),
			"excepted", exceptedCount,
			"evaluatedAt", now,
			"expiresAt", now+resultRetentionMs,
		)})
	}
	checkpointKey, _ := CheckpointID(tenantID)
	err = store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		results = nil
		counts := complianceEmptyCounts()
		for _, entry := range evaluated {
			read, result := entry.control, entry.result
			// The control may have changed or gone while the checks ran; results follow the stored one.
			control, err := tx.Get(ctx, "complianceControls", jsString(read.Get("id")))
			if err != nil {
				return err
			}
			if control == nil || control.Get("tenantId") != tenantID || !strictEquals(control.Get("key"), read.Get("key")) {
				continue
			}
			status := jsString(result.Get("status"))
			counts.Set(status, jsNumber(counts.Get(status))+1)
			if _, err := tx.Insert(ctx, "complianceResults", result); err != nil {
				return err
			}
			results = append(results, result)
			lastStatus := control.Get("lastStatus")
			if lastStatus != status && (status == "fail" || lastStatus == "fail") {
				action, outcome := "compliance:control:recover", "allow"
				if status == "fail" {
					action, outcome = "compliance:control:fail", "deny"
				}
				metadata := core.NewObject("key", control.Get("key"), "checkId", control.Get("checkId"), "status", status)
				if truthy(lastStatus) {
					metadata.Set("previous", lastStatus)
				}
				metadata.Set("summary", result.Get("summary"))
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", triggeredBy,
					"action", action,
					"resourceId", control.Get("id"),
					"timestamp", now,
					"outcome", outcome,
					"metadata", metadata,
				)); err != nil {
					return err
				}
			}
			if _, err := tx.Put(ctx, "complianceControls", control.Spread(core.NewObject(
				"lastStatus", status,
				"lastEvaluatedAt", now,
				"lastResultId", result.Get("id"),
			))); err != nil {
				return err
			}
		}
		if checkpoint != nil {
			saved, err := tx.Get(ctx, "complianceCheckpoints", checkpointKey)
			if err != nil {
				return err
			}
			record := core.NewObject(
				"id", checkpointKey,
				"tenantId", tenantID,
				"sequence", checkpoint.Get("sequence"),
				"hash", checkpoint.Get("hash"),
				"verifiedAt", now,
			)
			if saved == nil {
				if _, err := tx.Insert(ctx, "complianceCheckpoints", record); err != nil {
					return err
				}
			} else if jsNumber(saved.Get("sequence")) < jsNumber(checkpoint.Get("sequence")) {
				if _, err := tx.Put(ctx, "complianceCheckpoints", record); err != nil {
					return err
				}
			}
		}
		summaries := make([]any, len(results))
		for index, result := range results {
			summaries[index] = core.NewObject(
				"control", result.Get("controlKey"),
				"status", result.Get("status"),
				"findings", result.Get("findingsTotal"),
				"excepted", result.Get("excepted"),
				"metrics", result.Get("metrics"),
			)
		}
		sum := sha256.Sum256(utf8Bytes(core.CanonicalJSON(summaries)))
		digest := hex.EncodeToString(sum[:])
		run = core.NewObject(
			"id", runID,
			"tenantId", tenantID,
			"evaluatedAt", now,
			"counts", counts,
			"digest", digest,
			"triggeredBy", triggeredBy,
			"expiresAt", now+resultRetentionMs,
		)
		if _, err := tx.Insert(ctx, "complianceRuns", run); err != nil {
			return err
		}
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", triggeredBy,
			"action", "compliance:evaluate",
			"resourceId", runID,
			"timestamp", now,
			"outcome", "allow",
			"metadata", counts.Spread(core.NewObject("digest", digest)),
		))
	})
	if err != nil {
		return nil, nil, err
	}
	return run, results, nil
}

// complianceIsString reports whether a value is a string.
func complianceIsString(value any) bool {
	_, ok := value.(string)
	return ok
}

// complianceMax is Math.max of two numbers (NaN wins).
func complianceMax(a, b float64) float64 {
	if a != a || b != b {
		return a + b
	}
	if a > b {
		return a
	}
	return b
}

// runComplianceCheck evaluates a control's check with its effective parameters; a panic counts as a check that could not run.
func runComplianceCheck(ctx context.Context, server *ServerContext, store core.IamStore, check *ComplianceCheck, tenant, control *core.Object, now float64) (outcome *CheckOutcome, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			outcome, err = nil, core.NewIamError("INTERNAL_ERROR", jsString(recovered))
			if failure, ok := recovered.(error); ok {
				err = failure
			}
		}
	}()
	stored, _ := control.Get("params").(*core.Object)
	params, err := EffectiveParams(check, stored)
	if err != nil {
		return nil, err
	}
	return check.evaluate(ctx, server, store, tenant, params, now)
}

// orderedResults is an insertion-ordered Map<string, ComplianceResult>.
type orderedResults struct {
	keys  []string
	byKey map[string]*core.Object
}

func (r *orderedResults) set(key string, result *core.Object) {
	if _, ok := r.byKey[key]; !ok {
		r.keys = append(r.keys, key)
	}
	r.byKey[key] = result
}

func (r *orderedResults) values() []*core.Object {
	list := make([]*core.Object, len(r.keys))
	for index, key := range r.keys {
		list[index] = r.byKey[key]
	}
	return list
}

// latestComplianceResults is the newest result of each control, by its pointer (controls evaluated before pointers fall back
// to a lookup).
func latestComplianceResults(ctx context.Context, tx core.IamStore, tenantID string, controls []*core.Object) (*orderedResults, error) {
	latest := &orderedResults{byKey: map[string]*core.Object{}}
	for _, control := range controls {
		key := jsString(control.Get("key"))
		if lastResultID := control.Get("lastResultId"); truthy(lastResultID) {
			result, err := tx.Get(ctx, "complianceResults", jsString(lastResultID))
			if err != nil {
				return nil, err
			}
			if result != nil && result.Get("tenantId") == tenantID {
				latest.set(key, result)
			}
			continue
		}
		if isUndefined(control.Get("lastEvaluatedAt")) {
			continue
		}
		found, err := tx.Find(ctx, "complianceResults", core.NewObject("tenantId", tenantID, "controlKey", control.Get("key")), nil)
		if err != nil {
			return nil, err
		}
		for _, result := range found {
			current := -1.0
			if existing, ok := latest.byKey[key]; ok {
				current = jsNumber(coalesce(existing.Get("evaluatedAt"), -1.0))
			}
			if current < jsNumber(result.Get("evaluatedAt")) {
				latest.set(key, result)
			}
		}
	}
	return latest, nil
}

var complianceIdentitySubject = regexp.MustCompile(`^identity:([^:]+)`)

// directory is whether the caller may see people's names and addresses (`iam:identities:read`).
func (api *ComplianceAPI) directory(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (bool, error) {
	decision, err := api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{TenantID: tenantID, Action: "iam:identities:read", Resource: ResourceTarget{Type: "iam", ID: tenantID}}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// views is results as readers see them: names added for directory readers, staleness marked.
func (api *ComplianceAPI) views(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, results []*core.Object) ([]*core.Object, error) {
	names := map[string]string{}
	allowed, err := api.directory(ctx, tx, principal, tenantID)
	if err != nil {
		return nil, err
	}
	if allowed {
		var ids []string
		seen := map[string]bool{}
		for _, result := range results {
			findings, _ := result.Get("findings").([]any)
			for _, finding := range findings {
				subject, _ := member(finding, "subject").(string)
				if match := complianceIdentitySubject.FindStringSubmatch(subject); match != nil && !seen[match[1]] {
					seen[match[1]] = true
					ids = append(ids, match[1])
				}
			}
		}
		for _, identityID := range ids {
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			if identity != nil && identity.Get("tenantId") == tenantID {
				names[identityID] = jsString(coalesce(identity.Get("email"), identity.Get("name")))
			}
		}
	}
	now := float64(api.server.Now())
	shown := make([]*core.Object, len(results))
	for index, result := range results {
		findings, _ := result.Get("findings").([]any)
		mapped := make([]any, len(findings))
		for position, finding := range findings {
			mapped[position] = finding
			subject, _ := member(finding, "subject").(string)
			key := ""
			if match := complianceIdentitySubject.FindStringSubmatch(subject); match != nil {
				key = match[1]
			}
			if name := names[key]; name != "" {
				if record, ok := finding.(*core.Object); ok {
					mapped[position] = record.Spread(core.NewObject("name", name))
				}
			}
		}
		shown[index] = result.Spread(core.NewObject(
			"stale", jsNumber(result.Get("evaluatedAt")) < now-staleAfterMs,
			"findings", mapped,
		))
	}
	return shown, nil
}

// audit records an allowed compliance event.
func (api *ComplianceAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID string, resourceID any, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, tenantID, jsString(resourceID), "allow", false, metadata)
}

// complianceControlState is the audited state of a control.
func complianceControlState(control *core.Object) *core.Object {
	return core.NewObject(
		"name", control.Get("name"),
		"params", control.Get("params"),
		"mappings", control.Get("mappings"),
		"enabled", control.Get("enabled"),
	)
}

// frameworkOf is `frameworkById.get(text(value, 'framework', 32))`: the framework, or nil.
func frameworkOf(value any) (*core.Object, error) {
	id, err := Text(value, "framework", 32)
	if err != nil {
		return nil, err
	}
	framework, _ := FrameworkByID.Get(id).(*core.Object)
	return framework, nil
}

// frameworkList is complianceFrameworks.
func frameworkList() []*core.Object {
	items, _ := ComplianceFrameworks.([]any)
	list := make([]*core.Object, 0, len(items))
	for _, item := range items {
		if framework, ok := item.(*core.Object); ok {
			list = append(list, framework)
		}
	}
	return list
}

// mapsFramework is `control.mappings.some((ref) => ref.startsWith(`${framework.id}:`))`.
func mapsFramework(control *core.Object, framework *core.Object) bool {
	prefix := jsString(framework.Get("id")) + ":"
	for _, ref := range stringList(control.Get("mappings")) {
		if strings.HasPrefix(ref, prefix) {
			return true
		}
	}
	return false
}

// complianceControlsOf is the tenant's controls.
func complianceControlsOf(ctx context.Context, tx core.IamStore, tenantID any) ([]*core.Object, error) {
	return tx.Find(ctx, "complianceControls", core.NewObject("tenantId", tenantID), nil)
}

// AdoptFramework is POST {basePath}/compliance/adoptFramework. Adopts a framework: one control per check its
// requirements use. A control already running that check (the one keyed by the check's ID first, else the first by
// key) gains the framework's mappings instead. Returns the controls it created or extended.
func (api *ComplianceAPI) AdoptFramework(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceAdoptFrameworkInput]) (Out[apitypes.ComplianceAdoptFrameworkOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		framework, err := frameworkOf(input.Get("framework"))
		if err != nil {
			return nil, err
		}
		if framework == nil {
			ids := make([]string, 0)
			for _, item := range frameworkList() {
				ids = append(ids, jsString(item.Get("id")))
			}
			return nil, invalidInput("framework must be one of " + strings.Join(ids, ", "))
		}
		now := float64(server.Now())
		controls, err := complianceControlsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		complianceSortBy(controls, "key")
		var touched []*core.Object
		var checkOrder []string
		byCheck := map[string][]string{}
		requirements, _ := framework.Get("requirements").([]any)
		for _, requirement := range requirements {
			for _, checkID := range stringList(member(requirement, "checks")) {
				if _, ok := byCheck[checkID]; !ok {
					checkOrder = append(checkOrder, checkID)
				}
				byCheck[checkID] = append(byCheck[checkID], jsString(framework.Get("id"))+":"+jsString(member(requirement, "id")))
			}
		}
		for _, checkID := range checkOrder {
			refs := byCheck[checkID]
			check := CheckByID[checkID]
			var existing *core.Object
			for _, control := range controls {
				if control.Get("key") == checkID {
					existing = control
					break
				}
			}
			if existing == nil {
				for _, control := range controls {
					if control.Get("checkId") == checkID {
						existing = control
						break
					}
				}
			}
			if existing != nil {
				merged := unique(append(stringList(existing.Get("mappings")), refs...))
				sortStrings(merged)
				updated, err := tx.Put(ctx, "complianceControls", existing.Spread(core.NewObject("mappings", stringsOf(merged), "updatedAt", now)))
				if err != nil {
					return nil, err
				}
				touched = append(touched, updated)
				continue
			}
			if len(controls)+len(touched) >= maxComplianceControls {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+core.NumberString(maxComplianceControls)+" controls", 409)
			}
			for _, control := range controls {
				if control.Get("key") == checkID {
					return nil, core.NewIamError("CONFLICT", "A control keyed "+checkID+" runs another check", 409)
				}
			}
			params, err := CheckParams(check, core.Undefined)
			if err != nil {
				return nil, err
			}
			sorted := append([]string(nil), refs...)
			sortStrings(sorted)
			inserted, err := tx.Insert(ctx, "complianceControls", core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", "key:"+checkID,
				"key", checkID,
				"name", check.Title,
				"description", check.Description,
				"checkId", checkID,
				"params", params,
				"mappings", stringsOf(sorted),
				"enabled", true,
				"createdAt", now,
				"updatedAt", now,
			))
			if err != nil {
				return nil, err
			}
			touched = append(touched, inserted)
		}
		keys := make([]any, len(touched))
		for index, control := range touched {
			keys[index] = control.Get("key")
		}
		if err := api.audit(ctx, tx, principal, "compliance:framework:adopt", tenantID, tenantID, core.NewObject("framework", framework.Get("id"), "controls", keys)); err != nil {
			return nil, err
		}
		return core.NewObject("framework", framework.Get("id"), "controls", objectList(touched)), nil
	}, false)
	return Out[apitypes.ComplianceAdoptFrameworkOutput]{Value: result}, err
}

// ApproveException is POST {basePath}/compliance/approveException. Approves a pending exception: someone other than
// its author, and not the subject of the finding.
func (api *ComplianceAPI) ApproveException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceApproveExceptionInput]) (Out[apitypes.ComplianceApproveExceptionOutput], error) {
	server := api.server
	resource, err := Text(input.Get("exceptionId"), "exceptionId")
	if err != nil {
		return Out[apitypes.ComplianceApproveExceptionOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		exception, err := server.Scoped(ctx, tx, "complianceExceptions", input.Get("exceptionId"), tenantID)
		if err != nil {
			return nil, err
		}
		if complianceExceptionStatus(exception) != "pending" {
			return nil, core.NewIamError("CONFLICT", "The exception is not pending", 409)
		}
		if jsNumber(exception.Get("expiresAt")) <= float64(server.Now()) {
			return nil, core.NewIamError("CONFLICT", "The exception has expired", 409)
		}
		identityID := principal.Identity.Get("id")
		if exception.Get("createdBy") == identityID {
			return nil, core.NewIamError("ACCESS_DENIED", "A second person approves an exception", 403)
		}
		if namesIdentity(jsString(exception.Get("subject")), identityID) {
			return nil, core.NewIamError("ACCESS_DENIED", "An exception for your own finding needs someone else", 403)
		}
		approved, err := tx.Put(ctx, "complianceExceptions", exception.Spread(core.NewObject(
			"status", "approved",
			"approvedBy", identityID,
			"approvedAt", float64(server.Now()),
		)))
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "compliance:exception:approve", tenantID, exception.Get("id"), core.NewObject(
			"controlKey", exception.Get("controlKey"),
			"subject", exception.Get("subject"),
			"createdBy", exception.Get("createdBy"),
			"expiresAt", exception.Get("expiresAt"),
		)); err != nil {
			return nil, err
		}
		return approved, nil
	}, false)
	return Out[apitypes.ComplianceApproveExceptionOutput]{Value: result}, err
}

// Catalog is POST {basePath}/compliance/catalog. Returns the built-in checks with their parameters, and the framework
// mappings.
func (api *ComplianceAPI) Catalog(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCatalogInput]) (Out[apitypes.ComplianceCatalogOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		checks := make([]any, len(ComplianceChecks))
		for index, check := range ComplianceChecks {
			view := core.NewObject("id", check.ID, "title", check.Title, "description", check.Description, "params", core.CloneValue(objectList(check.Params)))
			if check.noExceptions() {
				view.Set("noExceptions", true)
			}
			checks[index] = view
		}
		return core.NewObject("checks", checks, "frameworks", core.CloneValue(ComplianceFrameworks)), nil
	}, false)
	return Out[apitypes.ComplianceCatalogOutput]{Value: result}, err
}

// CreateControl is POST {basePath}/compliance/createControl. Adds a control that runs one check with parameters and
// mappings of your own.
func (api *ComplianceAPI) CreateControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCreateControlInput]) (Out[apitypes.ComplianceCreateControlOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		key, err := complianceControlKey(input.Get("key"))
		if err != nil {
			return nil, err
		}
		checkID, err := Text(input.Get("checkId"), "checkId", 64)
		if err != nil {
			return nil, err
		}
		check := CheckByID[checkID]
		if check == nil {
			return nil, invalidInput("Unknown check " + checkID)
		}
		controls, err := complianceControlsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, control := range controls {
			if control.Get("key") == key {
				return nil, core.NewIamError("CONFLICT", "A control with this key exists", 409)
			}
		}
		if len(controls) >= maxComplianceControls {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+core.NumberString(maxComplianceControls)+" controls", 409)
		}
		enabled := input.Get("enabled")
		if _, ok := enabled.(bool); !isUndefined(enabled) && !ok {
			return nil, invalidInput("enabled must be a boolean")
		}
		now := float64(server.Now())
		name, err := Text(input.Get("name"), "name", 120)
		if err != nil {
			return nil, err
		}
		record := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", "key:"+key, "key", key, "name", core.JSTrim(name))
		if description := input.Get("description"); truthy(description) {
			text, err := Text(description, "description", 1000)
			if err != nil {
				return nil, err
			}
			record.Set("description", text)
		}
		params, err := CheckParams(check, input.Get("params"))
		if err != nil {
			return nil, err
		}
		mappings, err := complianceMappings(input.Get("mappings"))
		if err != nil {
			return nil, err
		}
		record.Set("checkId", check.ID)
		record.Set("params", params)
		record.Set("mappings", mappings)
		record.Set("enabled", coalesce(enabled, true))
		record.Set("createdAt", now)
		record.Set("updatedAt", now)
		control, err := tx.Insert(ctx, "complianceControls", record)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("key", key, "checkId", check.ID).Spread(complianceControlState(control))
		if err := api.audit(ctx, tx, principal, "compliance:control:create", tenantID, control.Get("id"), metadata); err != nil {
			return nil, err
		}
		return control, nil
	}, false)
	return Out[apitypes.ComplianceCreateControlOutput]{Value: result}, err
}

// CreateException is POST {basePath}/compliance/createException. Proposes accepting a finding for a while (a
// compensating control, a planned fix). It covers the finding only once a second person approves it
// (`approveException`), until `expiresAt` (at most a year). Nobody may propose or approve an exception for a finding
// about themselves, and audit-integrity findings cannot be excepted.
func (api *ComplianceAPI) CreateException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCreateExceptionInput]) (Out[apitypes.ComplianceCreateExceptionOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		key, err := complianceControlKey(input.Get("controlKey"))
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "complianceControls", core.NewObject("tenantId", tenantID, "key", key), nil)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, core.NewIamError("NOT_FOUND", "Control not found", 404)
		}
		control := found[0]
		if checkID, ok := control.Get("checkId").(string); ok && CheckByID[checkID] != nil && CheckByID[checkID].noExceptions() {
			return nil, invalidInput("Findings of " + checkID + " cannot be excepted")
		}
		subject, err := Text(input.Get("subject"), "subject", 300)
		if err != nil {
			return nil, err
		}
		identityID := principal.Identity.Get("id")
		if namesIdentity(subject, identityID) {
			return nil, core.NewIamError("ACCESS_DENIED", "An exception for your own finding needs someone else", 403)
		}
		now := float64(server.Now())
		expiresAt, err := Integer(input.Get("expiresAt"), "expiresAt", now+60_000, now+366*86_400_000)
		if err != nil {
			return nil, err
		}
		reason, err := Text(input.Get("reason"), "reason", 1000)
		if err != nil {
			return nil, err
		}
		exception := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"controlKey", key,
			"subject", subject,
			"reason", reason,
			"expiresAt", expiresAt,
			"createdBy", identityID,
			"createdAt", now,
			"status", "pending",
		)
		if _, err := tx.Insert(ctx, "complianceExceptions", exception); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "compliance:exception", tenantID, exception.Get("id"), core.NewObject(
			"controlKey", key,
			"subject", subject,
			"expiresAt", expiresAt,
			"status", "pending",
		)); err != nil {
			return nil, err
		}
		return exception, nil
	}, false)
	return Out[apitypes.ComplianceCreateExceptionOutput]{Value: result}, err
}

// DeleteControl is POST {basePath}/compliance/deleteControl. Deletes a control; its exceptions end (kept as revoked
// history) and its past results stay until they expire.
func (api *ComplianceAPI) DeleteControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceDeleteControlInput]) (Out[apitypes.ComplianceDeleteControlOutput], error) {
	server := api.server
	resource, err := Text(input.Get("controlId"), "controlId")
	if err != nil {
		return Out[apitypes.ComplianceDeleteControlOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		control, err := server.Scoped(ctx, tx, "complianceControls", input.Get("controlId"), tenantID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		exceptions, err := tx.Find(ctx, "complianceExceptions", core.NewObject("tenantId", tenantID, "controlKey", control.Get("key")), nil)
		if err != nil {
			return nil, err
		}
		for _, exception := range exceptions {
			if complianceExceptionStatus(exception) != "revoked" {
				if _, err := tx.Put(ctx, "complianceExceptions", exception.Spread(core.NewObject(
					"status", "revoked",
					"revokedBy", principal.Identity.Get("id"),
					"revokedAt", now,
				))); err != nil {
					return nil, err
				}
			}
		}
		if err := tx.Delete(ctx, "complianceControls", jsString(control.Get("id"))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "compliance:control:delete", tenantID, control.Get("id"), core.NewObject(
			"key", control.Get("key"),
			"checkId", control.Get("checkId"),
			"before", complianceControlState(control),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ComplianceDeleteControlOutput]{Value: result}, err
}

// Evaluate is POST {basePath}/compliance/evaluate. Runs the enabled controls (or `controlKeys`) now, at most once a
// minute per tenant. Audited as `compliance:evaluate` with the run's digest. Returns the run and each control's status
// and counts; the findings are read with `listResults` (which needs `iam:compliance:read`).
func (api *ComplianceAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceEvaluateInput]) (Out[apitypes.ComplianceEvaluateOutput], error) {
	server := api.server
	var keys []string
	if controlKeys := input.Get("controlKeys"); !isUndefined(controlKeys) {
		list, err := Strings(controlKeys, "controlKeys")
		if err != nil {
			return Out[apitypes.ComplianceEvaluateOutput]{}, err
		}
		keys = list
	}
	rawTenantID := input.Get("tenantId")
	caller, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:evaluate", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (any, error) {
		return call.Principal.Identity.Get("id"), nil
	}, false)
	if err != nil {
		return Out[apitypes.ComplianceEvaluateOutput]{}, err
	}
	tenantID, err := Text(rawTenantID, "tenantId")
	if err != nil {
		return Out[apitypes.ComplianceEvaluateOutput]{}, err
	}
	run, results, err := runComplianceEvaluation(ctx, server, tenantID, caller, keys, manualIntervalMs)
	if err != nil {
		return Out[apitypes.ComplianceEvaluateOutput]{}, err
	}
	summaries := make([]any, len(results))
	for index, result := range results {
		summaries[index] = core.NewObject(
			"controlKey", result.Get("controlKey"),
			"checkId", result.Get("checkId"),
			"status", result.Get("status"),
			"rawStatus", result.Get("rawStatus"),
			"summary", result.Get("summary"),
			"findingsTotal", result.Get("findingsTotal"),
			"excepted", result.Get("excepted"),
		)
	}
	return Out[apitypes.ComplianceEvaluateOutput]{Value: core.NewObject("run", run, "results", summaries)}, nil
}

// EvidenceKeys is POST {basePath}/compliance/evidenceKeys. The public keys evidence packs are signed with (JWKS; the
// current key first), for auditors' offline checks.
func (api *ComplianceAPI) EvidenceKeys(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceEvidenceKeysInput]) (Out[apitypes.ComplianceEvidenceKeysOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return core.NewObject("keys", objectList(api.evidenceJWKs())), nil
	}, false)
	return Out[apitypes.ComplianceEvidenceKeysOutput]{Value: result}, err
}

// secrets is the deployment secret and the previous ones.
func (api *ComplianceAPI) secrets() []string {
	options := api.server.Options
	return append([]string{options.Secret}, options.PreviousSecrets...)
}

// evidenceJWKs is the public JWK of every secret's evidence key (fresh copies).
func (api *ComplianceAPI) evidenceJWKs() []*core.Object {
	secrets := api.secrets()
	keys := make([]*core.Object, len(secrets))
	for index, secret := range secrets {
		keys[index] = evidenceKey(secret).jwk.Clone()
	}
	return keys
}

// ExportEvidence is POST {basePath}/compliance/exportEvidence. An evidence pack for auditors: the controls (of one
// framework, or all; disabled ones included and marked), their latest results with findings (stale ones marked),
// every exception with its history, recent runs, and the audit chain head. Signed with the deployment's Ed25519
// evidence key; the pack's digest is recorded in the audit chain (`compliance:evidence-export`). Findings name people
// only when the caller may read the directory.
func (api *ComplianceAPI) ExportEvidence(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceExportEvidenceInput]) (Out[apitypes.ComplianceExportEvidenceOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		var framework *core.Object
		if value := input.Get("framework"); !isUndefined(value) {
			found, err := frameworkOf(value)
			if err != nil {
				return nil, err
			}
			if found == nil {
				return nil, invalidInput("Unknown framework")
			}
			framework = found
		}
		now := float64(server.Now())
		all, err := complianceControlsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		var controls []*core.Object
		for _, control := range all {
			if framework == nil || mapsFramework(control, framework) {
				controls = append(controls, control)
			}
		}
		complianceSortBy(controls, "key")
		latest, err := latestComplianceResults(ctx, tx, tenantID, controls)
		if err != nil {
			return nil, err
		}
		views, err := api.views(ctx, tx, principal, tenantID, latest.values())
		if err != nil {
			return nil, err
		}
		shown := map[string]*core.Object{}
		for _, view := range views {
			shown[jsString(view.Get("controlKey"))] = view
		}
		keys := map[string]bool{}
		for _, control := range controls {
			keys[jsString(control.Get("key"))] = true
		}
		head, err := tx.Get(ctx, "auditChains", tenantID)
		if err != nil {
			return nil, err
		}
		body := core.NewObject(
			"format", "better-iam.compliance-evidence",
			"version", 2.0,
			"generatedAt", isoString(now),
			"tenant", core.NewObject("id", tenant.Get("id"), "name", tenant.Get("name")),
		)
		if framework != nil {
			body.Set("framework", core.NewObject("id", framework.Get("id"), "name", framework.Get("name")))
		}
		controlViews := make([]any, len(controls))
		for index, control := range controls {
			view := core.NewObject(
				"key", control.Get("key"),
				"name", control.Get("name"),
				"checkId", control.Get("checkId"),
				"params", control.Get("params"),
				"mappings", control.Get("mappings"),
				"enabled", control.Get("enabled"),
			)
			if result := shown[jsString(control.Get("key"))]; result != nil {
				view.Set("result", core.NewObject(
					"runId", result.Get("runId"),
					"status", result.Get("status"),
					"rawStatus", result.Get("rawStatus"),
					"summary", result.Get("summary"),
					"metrics", result.Get("metrics"),
					"findings", result.Get("findings"),
					"findingsTotal", result.Get("findingsTotal"),
					"excepted", result.Get("excepted"),
					"evaluatedAt", result.Get("evaluatedAt"),
					"stale", result.Get("stale"),
				))
			}
			controlViews[index] = view
		}
		body.Set("controls", controlViews)
		exceptionRecords, err := tx.Find(ctx, "complianceExceptions", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var included []*core.Object
		for _, exception := range exceptionRecords {
			if keys[jsString(exception.Get("controlKey"))] && complianceIsString(exception.Get("controlKey")) {
				included = append(included, exception)
			}
		}
		sort.SliceStable(included, func(i, j int) bool {
			return jsNumber(included[i].Get("createdAt")) < jsNumber(included[j].Get("createdAt"))
		})
		exceptionViews := make([]any, len(included))
		for index, exception := range included {
			view := core.NewObject(
				"controlKey", exception.Get("controlKey"),
				"subject", exception.Get("subject"),
				"reason", exception.Get("reason"),
				"expiresAt", exception.Get("expiresAt"),
				"createdBy", exception.Get("createdBy"),
				"createdAt", exception.Get("createdAt"),
				"status", complianceExceptionStatus(exception),
			)
			if truthy(exception.Get("approvedBy")) {
				view.Set("approvedBy", exception.Get("approvedBy"))
				view.Set("approvedAt", exception.Get("approvedAt"))
			}
			if truthy(exception.Get("revokedBy")) {
				view.Set("revokedBy", exception.Get("revokedBy"))
				view.Set("revokedAt", exception.Get("revokedAt"))
			}
			exceptionViews[index] = view
		}
		body.Set("exceptions", exceptionViews)
		runs, err := tx.Find(ctx, "complianceRuns", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(runs, func(i, j int) bool {
			return jsNumber(runs[i].Get("evaluatedAt")) > jsNumber(runs[j].Get("evaluatedAt"))
		})
		if len(runs) > 30 {
			runs = runs[:30]
		}
		runViews := make([]any, len(runs))
		for index, run := range runs {
			runViews[index] = core.NewObject("id", run.Get("id"), "evaluatedAt", run.Get("evaluatedAt"), "counts", run.Get("counts"), "digest", run.Get("digest"))
		}
		body.Set("runs", runViews)
		if head != nil {
			body.Set("auditHead", core.NewObject("sequence", head.Get("sequence"), "hash", head.Get("hash")))
		}
		digest := evidencePackDigest(body)
		key := evidenceKey(server.Options.Secret)
		metadata := core.NewObject()
		if framework != nil {
			metadata.Set("framework", framework.Get("id"))
		}
		metadata.Set("controls", float64(len(controls)))
		metadata.Set("digest", digest)
		metadata.Set("kid", key.kid)
		if err := api.audit(ctx, tx, principal, "compliance:evidence-export", tenantID, tenantID, metadata); err != nil {
			return nil, err
		}
		return body.Spread(core.NewObject(
			"digest", digest,
			"signature", core.NewObject("alg", "EdDSA", "kid", key.kid, "value", base64url(ed25519.Sign(key.privateKey, utf8Bytes(digest)))),
		)), nil
	}, false)
	return Out[apitypes.ComplianceExportEvidenceOutput]{Value: result}, err
}

// ListControls is POST {basePath}/compliance/listControls. Lists the tenant's controls by name, each with its latest
// result.
func (api *ComplianceAPI) ListControls(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListControlsInput]) (Out[apitypes.ComplianceListControlsOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		controls, err := complianceControlsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(controls, func(i, j int) bool {
			return localeCompare(jsString(controls[i].Get("name")), jsString(controls[j].Get("name"))) < 0
		})
		latest, err := latestComplianceResults(ctx, tx, tenantID, controls)
		if err != nil {
			return nil, err
		}
		shown, err := api.views(ctx, tx, principal, tenantID, latest.values())
		if err != nil {
			return nil, err
		}
		byKey := map[string]*core.Object{}
		for _, result := range shown {
			byKey[jsString(result.Get("controlKey"))] = result
		}
		list := make([]any, len(controls))
		for index, control := range controls {
			var latestView any = core.Undefined
			if view, ok := byKey[jsString(control.Get("key"))]; ok {
				latestView = view
			}
			list[index] = control.Spread(core.NewObject("latest", latestView))
		}
		return list, nil
	}, false)
	return Out[apitypes.ComplianceListControlsOutput]{Value: result}, err
}

// ListExceptions is POST {basePath}/compliance/listExceptions. Every exception with its status; `active` ones cover
// findings now. Records are kept 400 days after expiry.
func (api *ComplianceAPI) ListExceptions(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListExceptionsInput]) (Out[apitypes.ComplianceListExceptionsOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		now := float64(api.server.Now())
		exceptions, err := call.Tx.Find(ctx, "complianceExceptions", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		views := make([]*core.Object, len(exceptions))
		for index, exception := range exceptions {
			views[index] = exception.Spread(core.NewObject("status", complianceExceptionStatus(exception), "active", exceptionActive(exception, now)))
		}
		sort.SliceStable(views, func(i, j int) bool {
			return jsNumber(views[i].Get("expiresAt")) < jsNumber(views[j].Get("expiresAt"))
		})
		return objectList(views), nil
	}, false)
	return Out[apitypes.ComplianceListExceptionsOutput]{Value: result}, err
}

// ListResults is POST {basePath}/compliance/listResults. Results, newest first: of one control (its history), of one
// run, or the latest of every control.
func (api *ComplianceAPI) ListResults(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListResultsInput]) (Out[apitypes.ComplianceListResultsOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		controlKey, runID := input.Get("controlKey"), input.Get("runId")
		if isUndefined(controlKey) && isUndefined(runID) {
			controls, err := complianceControlsOf(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			latest, err := latestComplianceResults(ctx, tx, tenantID, controls)
			if err != nil {
				return nil, err
			}
			results := latest.values()
			complianceSortBy(results, "controlKey")
			views, err := api.views(ctx, tx, principal, tenantID, results)
			if err != nil {
				return nil, err
			}
			return objectList(views), nil
		}
		filter := core.NewObject("tenantId", tenantID)
		if !isUndefined(controlKey) {
			key, err := Text(controlKey, "controlKey", 64)
			if err != nil {
				return nil, err
			}
			filter.Set("controlKey", key)
		}
		if !isUndefined(runID) {
			id, err := Text(runID, "runId")
			if err != nil {
				return nil, err
			}
			filter.Set("runId", id)
		}
		results, err := tx.Find(ctx, "complianceResults", filter, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(results, func(i, j int) bool {
			a, b := jsNumber(results[i].Get("evaluatedAt")), jsNumber(results[j].Get("evaluatedAt"))
			if a != b {
				return a > b
			}
			return compareUTF16(jsString(results[i].Get("controlKey")), jsString(results[j].Get("controlKey"))) < 0
		})
		if len(results) > int(limit) {
			results = results[:int(limit)]
		}
		views, err := api.views(ctx, tx, principal, tenantID, results)
		if err != nil {
			return nil, err
		}
		return objectList(views), nil
	}, false)
	return Out[apitypes.ComplianceListResultsOutput]{Value: result}, err
}

// ListRuns is POST {basePath}/compliance/listRuns. Lists evaluation runs, newest first.
func (api *ComplianceAPI) ListRuns(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListRunsInput]) (Out[apitypes.ComplianceListRunsOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		runs, err := call.Tx.Find(ctx, "complianceRuns", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(runs, func(i, j int) bool {
			return jsNumber(runs[i].Get("evaluatedAt")) > jsNumber(runs[j].Get("evaluatedAt"))
		})
		limit, err := Integer(coalesce(input.Get("limit"), 30.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		if len(runs) > int(limit) {
			runs = runs[:int(limit)]
		}
		return objectList(runs), nil
	}, false)
	return Out[apitypes.ComplianceListRunsOutput]{Value: result}, err
}

// RevokeException is POST {basePath}/compliance/revokeException. Ends an exception (or withdraws a pending one); the
// record stays as history.
func (api *ComplianceAPI) RevokeException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceRevokeExceptionInput]) (Out[apitypes.ComplianceRevokeExceptionOutput], error) {
	server := api.server
	resource, err := Text(input.Get("exceptionId"), "exceptionId")
	if err != nil {
		return Out[apitypes.ComplianceRevokeExceptionOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		exception, err := server.Scoped(ctx, tx, "complianceExceptions", input.Get("exceptionId"), tenantID)
		if err != nil {
			return nil, err
		}
		if complianceExceptionStatus(exception) == "revoked" {
			return core.NewObject("revoked", true), nil
		}
		if _, err := tx.Put(ctx, "complianceExceptions", exception.Spread(core.NewObject(
			"status", "revoked",
			"revokedBy", principal.Identity.Get("id"),
			"revokedAt", float64(server.Now()),
		))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "compliance:exception:revoke", tenantID, exception.Get("id"), core.NewObject(
			"controlKey", exception.Get("controlKey"),
			"subject", exception.Get("subject"),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", true), nil
	}, false)
	return Out[apitypes.ComplianceRevokeExceptionOutput]{Value: result}, err
}

// Status is POST {basePath}/compliance/status. Each framework's requirements with the latest status of the controls
// that evidence them.
func (api *ComplianceAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceStatusInput]) (Out[apitypes.ComplianceStatusOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		var selected *core.Object
		if value := input.Get("framework"); !isUndefined(value) {
			found, err := frameworkOf(value)
			if err != nil {
				return nil, err
			}
			if found == nil {
				return nil, invalidInput("Unknown framework")
			}
			selected = found
		}
		controls, err := complianceControlsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		latest, err := latestComplianceResults(ctx, tx, tenantID, controls)
		if err != nil {
			return nil, err
		}
		now := float64(api.server.Now())
		var frameworks []*core.Object
		if selected != nil {
			frameworks = []*core.Object{selected}
		} else {
			for _, framework := range frameworkList() {
				for _, control := range controls {
					if mapsFramework(control, framework) {
						frameworks = append(frameworks, framework)
						break
					}
				}
			}
		}
		statuses := make([]any, len(frameworks))
		for index, framework := range frameworks {
			requirementList, _ := framework.Get("requirements").([]any)
			requirements := make([]*core.Object, len(requirementList))
			for position, requirement := range requirementList {
				ref := jsString(framework.Get("id")) + ":" + jsString(member(requirement, "id"))
				var mappedControls []*core.Object
				for _, control := range controls {
					if containsString(stringList(control.Get("mappings")), ref) {
						mappedControls = append(mappedControls, control)
					}
				}
				complianceSortBy(mappedControls, "key")
				mapped := make([]any, len(mappedControls))
				var requirementStatus string
				for slot, control := range mappedControls {
					view := core.NewObject("key", control.Get("key"), "name", control.Get("name"), "enabled", control.Get("enabled"))
					result, found := latest.byKey[jsString(control.Get("key"))]
					stale := false
					if found {
						stale = jsNumber(result.Get("evaluatedAt")) < now-staleAfterMs
						view.Set("status", result.Get("status"))
						view.Set("evaluatedAt", result.Get("evaluatedAt"))
						view.Set("stale", stale)
					}
					mapped[slot] = view
					var status string
					switch {
					case !truthy(control.Get("enabled")):
						status = "disabled"
					case !found || isUndefined(result.Get("status")) || stale:
						status = "not-evaluated"
					default:
						status = jsString(result.Get("status"))
					}
					if slot == 0 || requirementSeverity[status] > requirementSeverity[requirementStatus] {
						requirementStatus = status
					}
				}
				if len(mappedControls) == 0 {
					requirementStatus = "no-control"
				}
				requirements[position] = core.NewObject(
					"id", member(requirement, "id"),
					"title", member(requirement, "title"),
					"status", requirementStatus,
					"controls", mapped,
				)
			}
			covered, passing := 0.0, 0.0
			for _, requirement := range requirements {
				status := requirement.Get("status")
				if status == "no-control" {
					continue
				}
				covered++
				if status == "pass" || status == "not-applicable" {
					passing++
				}
			}
			statuses[index] = core.NewObject(
				"framework", core.NewObject("id", framework.Get("id"), "name", framework.Get("name")),
				"total", float64(len(requirements)),
				"covered", covered,
				"passing", passing,
				"requirements", objectList(requirements),
			)
		}
		return statuses, nil
	}, false)
	return Out[apitypes.ComplianceStatusOutput]{Value: result}, err
}

// UpdateControl is POST {basePath}/compliance/updateControl. Changes a control; audited as
// `compliance:control:update` with its state before and after.
func (api *ComplianceAPI) UpdateControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceUpdateControlInput]) (Out[apitypes.ComplianceUpdateControlOutput], error) {
	server := api.server
	resource, err := Text(input.Get("controlId"), "controlId")
	if err != nil {
		return Out[apitypes.ComplianceUpdateControlOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:compliance:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		control, err := server.Scoped(ctx, tx, "complianceControls", input.Get("controlId"), tenantID)
		if err != nil {
			return nil, err
		}
		checkID, _ := control.Get("checkId").(string)
		check := CheckByID[checkID]
		enabled := input.Get("enabled")
		if _, ok := enabled.(bool); !isUndefined(enabled) && !ok {
			return nil, invalidInput("enabled must be a boolean")
		}
		changes := core.NewObject()
		if name := input.Get("name"); !isUndefined(name) {
			text, err := Text(name, "name", 120)
			if err != nil {
				return nil, err
			}
			changes.Set("name", core.JSTrim(text))
		}
		if description := input.Get("description"); !isUndefined(description) {
			text, err := Text(description, "description", 1000)
			if err != nil {
				return nil, err
			}
			changes.Set("description", text)
		}
		if params := input.Get("params"); !isUndefined(params) {
			if check == nil {
				return nil, core.NewIamError("INTERNAL_ERROR", "Cannot read properties of undefined (reading 'params')")
			}
			checked, err := CheckParams(check, params)
			if err != nil {
				return nil, err
			}
			changes.Set("params", checked)
		}
		if mappings := input.Get("mappings"); !isUndefined(mappings) {
			list, err := complianceMappings(mappings)
			if err != nil {
				return nil, err
			}
			changes.Set("mappings", list)
		}
		if !isUndefined(enabled) {
			changes.Set("enabled", enabled)
		}
		changes.Set("updatedAt", float64(server.Now()))
		updated, err := tx.Put(ctx, "complianceControls", control.Spread(changes))
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "compliance:control:update", tenantID, control.Get("id"), core.NewObject(
			"key", control.Get("key"),
			"before", complianceControlState(control),
			"after", complianceControlState(updated),
		)); err != nil {
			return nil, err
		}
		return updated, nil
	}, false)
	return Out[apitypes.ComplianceUpdateControlOutput]{Value: result}, err
}

// VerifyEvidence is POST {basePath}/compliance/verifyEvidence. Whether an evidence pack is unaltered and was signed by
// this deployment (current or previous secret). Pass the `pack`, or only its `digest` and `signature` when the pack
// is too large to send.
func (api *ComplianceAPI) VerifyEvidence(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceVerifyEvidenceInput]) (Out[apitypes.ComplianceVerifyEvidenceOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:compliance:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenant := call.Tenant
		secrets := api.secrets()
		jwks := api.evidenceJWKs()
		if isUndefined(input.Get("pack")) {
			digest, err := Text(input.Get("digest"), "digest", 100)
			if err != nil {
				return nil, err
			}
			signature, err := Object(input.Get("signature"))
			if err != nil {
				return nil, err
			}
			var key *core.Object
			for _, item := range jwks {
				if strictEquals(item.Get("kid"), signature.Get("kid")) {
					key = item
					break
				}
			}
			value, ok := signature.Get("value").(string)
			if key == nil || !ok {
				return core.NewObject("valid", false), nil
			}
			return core.NewObject("valid", verifyEd25519JWK(key.Get("x"), digest, value)), nil
		}
		pack, err := Object(input.Get("pack"))
		if err != nil {
			return nil, err
		}
		if !strictEquals(member(pack.Get("tenant"), "id"), tenant.Get("id")) {
			return core.NewObject("valid", false), nil
		}
		if signature, ok := pack.Get("signature").(string); ok && strictEquals(pack.Get("version"), 1.0) {
			body := pack.Clone()
			body.Delete("signature")
			valid := false
			for _, secret := range secrets {
				if SameHash(evidenceLegacySignature(secret, body), signature) {
					valid = true
					break
				}
			}
			return core.NewObject("valid", valid), nil
		}
		return core.NewObject("valid", VerifyEvidencePack(pack, objectList(jwks)).Get("valid")), nil
	}, false)
	return Out[apitypes.ComplianceVerifyEvidenceOutput]{Value: result}, err
}

// ComplianceRuntime is api/compliance.ts createComplianceRuntime().
type ComplianceRuntime struct {
	server *ServerContext
}

// EvaluateAll (api/compliance.ts createComplianceRuntime().evaluateAll): Evaluates every active tenant (or one) that
// has enabled controls, one after another. A tenant's failure is reported in `failed` and never stops the others.
func (s *ComplianceRuntime) EvaluateAll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	filter := core.NewObject()
	if tenantID := member(input, "tenantId"); !isUndefined(tenantID) {
		id, err := Text(tenantID, "tenantId")
		if err != nil {
			return nil, err
		}
		filter.Set("tenantId", id)
	}
	controls, err := server.Store.Find(ctx, "complianceControls", filter, nil)
	if err != nil {
		return nil, err
	}
	var tenants []string
	for _, control := range controls {
		if truthy(control.Get("enabled")) {
			tenants = append(tenants, jsString(control.Get("tenantId")))
		}
	}
	tenants = unique(tenants)
	sortStrings(tenants)
	evaluated, failed := []any{}, []any{}
	for _, tenantID := range tenants {
		tenant, err := server.Store.Get(ctx, "tenants", tenantID)
		if err != nil {
			return nil, err
		}
		if tenant == nil || tenant.Get("status") != "active" {
			continue
		}
		run, _, err := runComplianceEvaluation(ctx, server, tenantID, "deployment-operator", nil, 0)
		if err != nil {
			code := "INTERNAL_ERROR"
			if known, ok := asIamError(err); ok {
				code = known.Code
			}
			failed = append(failed, core.NewObject("tenantId", tenantID, "code", code, "message", complianceSlice(errorMessage(err), 300)))
			continue
		}
		evaluated = append(evaluated, core.NewObject("tenantId", tenantID, "runId", run.Get("id"), "counts", run.Get("counts")))
	}
	return core.NewObject("evaluated", evaluated, "failed", failed), nil
}

// CreateComplianceRuntime builds the ComplianceRuntime (api/compliance.ts createComplianceRuntime).
func CreateComplianceRuntime(server *ServerContext) *ComplianceRuntime {
	return &ComplianceRuntime{server: server}
}
