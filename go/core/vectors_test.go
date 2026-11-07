package core_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// Every core-owned vector of spec/vectors is reproduced here from its input.

func undefinedOr(value any, ok bool) any {
	if !ok {
		return core.Undefined
	}
	return value
}

func str(o *core.Object, key string) string {
	text, _ := o.String(key)
	return text
}

func obj(o *core.Object, key string) *core.Object {
	value, _ := o.Get(key).(*core.Object)
	return value
}

func TestJCSVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "jcs").Cases {
		text, err := core.CanonicalizeJSON(c.Input.Get("value"))
		spectest.Check(t, c, spectest.Outcome(text, err))
	}
}

func TestCanonicalJSONVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "canonical-json").Cases {
		spectest.Check(t, c, core.CanonicalJSON(c.Input.Get("value")))
	}
}

// memoryStore mirrors the generator's minimal in-memory store (get/insert/put/find).
type memoryStore struct {
	rows map[string]*core.Object
}

func (m *memoryStore) key(collection, id string) string { return collection + "\u0000" + id }
func (m *memoryStore) Get(_ context.Context, collection, id string) (*core.Object, error) {
	if row, ok := m.rows[m.key(collection, id)]; ok {
		return row.Clone(), nil
	}
	return nil, nil
}
func (m *memoryStore) Find(context.Context, string, *core.Object, *core.FindOptions) ([]*core.Object, error) {
	return nil, errors.New("unused")
}
func (m *memoryStore) Insert(_ context.Context, collection string, record *core.Object) (*core.Object, error) {
	key := m.key(collection, str(record, "id"))
	if _, ok := m.rows[key]; ok {
		return nil, errors.New("duplicate")
	}
	m.rows[key] = record.Clone()
	return record, nil
}
func (m *memoryStore) Put(_ context.Context, collection string, record *core.Object) (*core.Object, error) {
	m.rows[m.key(collection, str(record, "id"))] = record.Clone()
	return record, nil
}
func (m *memoryStore) Delete(context.Context, string, string) error { return nil }
func (m *memoryStore) Transaction(ctx context.Context, fn core.TxFunc) error {
	return fn(ctx, m)
}
func (m *memoryStore) Migrate(context.Context) error { return nil }
func (m *memoryStore) Close(context.Context) error   { return nil }

func verifyOptions(value any) core.VerifyAuditChainOptions {
	var options core.VerifyAuditChainOptions
	o, _ := value.(*core.Object)
	if o == nil {
		return options
	}
	if previous, ok := o.String("previousHash"); ok {
		options.PreviousHash = &previous
	}
	if head, ok := o.Object("head"); ok {
		sequence, _ := head.Number("sequence")
		hash, _ := head.String("hash")
		options.Head = &core.AuditChainHeadRef{Sequence: sequence, Hash: hash}
	}
	return options
}

func objects(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		out = append(out, item.(*core.Object))
	}
	return out
}

func TestAuditChainVectors(t *testing.T) {
	store := &memoryStore{rows: map[string]*core.Object{}}
	ctx := context.Background()
	for _, c := range spectest.Load(t, "audit-chain").Cases {
		switch {
		case strings.HasPrefix(c.Name, "hash "):
			spectest.Check(t, c, core.AuditEventHash(obj(c.Input, "event")))
		case strings.HasPrefix(c.Name, "append "):
			event := obj(c.Input, "event")
			appended, err := core.AppendAuditEvent(ctx, store, event)
			if err != nil {
				t.Fatal(err)
			}
			head, _ := store.Get(ctx, "auditChains", str(event, "tenantId"))
			spectest.Check(t, c, core.NewObject("event", appended, "head", head))
		case strings.HasPrefix(c.Name, "verify "):
			result := core.VerifyAuditChain(objects(c.Input.Get("events")), verifyOptions(c.Input.Get("options")))
			spectest.Check(t, c, spectest.Model(result))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func decisionOutcome(decision core.Decision, err error) any {
	return spectest.Outcome(decision, err)
}

func TestPolicyEvaluationVectors(t *testing.T) {
	for _, file := range []string{"policy-evaluation", "policy-conditions"} {
		for _, c := range spectest.Load(t, file).Cases {
			spectest.Check(t, c, decisionOutcome(core.EvaluatePolicyValue(c.Input)))
		}
	}
}

func TestPolicyValidationVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "policy-validation").Cases {
		err := core.ValidatePolicy(c.Input.Get("document"))
		if err != nil {
			spectest.Check(t, c, spectest.ErrorValue(err))
		} else {
			spectest.Check(t, c, nil)
		}
	}
}

func TestPolicyPatternVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "policy-patterns").Cases {
		context := obj(c.Input, "context")
		switch strings.SplitN(c.Name, " ", 2)[0] {
		case "matchPattern":
			spectest.Check(t, c, core.MatchPattern(str(c.Input, "pattern"), str(c.Input, "value"), context))
		case "resolvePolicyValue":
			spectest.Check(t, c, undefinedOr(core.ResolvePolicyValue(str(c.Input, "value"), context)))
		case "validPolicyVariables":
			spectest.Check(t, c, core.ValidPolicyVariables(str(c.Input, "value")))
		case "isIpRange":
			spectest.Check(t, c, core.IsIPRange(str(c.Input, "value")))
		case "ipMatches":
			spectest.Check(t, c, core.IPMatches(str(c.Input, "address"), str(c.Input, "network")))
		case "ipCounterKey":
			spectest.Check(t, c, undefinedOr(core.IPCounterKey(str(c.Input, "value"))))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func filterOf(t *testing.T, value any) core.ResourceFilter {
	t.Helper()
	filter, err := core.FilterFromValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func filtersOf(t *testing.T, value any) []core.ResourceFilter {
	list, _ := value.([]any)
	out := make([]core.ResourceFilter, 0, len(list))
	for _, item := range list {
		out = append(out, filterOf(t, item))
	}
	return out
}

func planOf(t *testing.T, value any) core.ResourcePlan {
	o := value.(*core.Object)
	return core.ResourcePlan{Kind: str(o, "kind"), Filter: filterOf(t, o.Get("filter"))}
}

func planInput(t *testing.T, o *core.Object) core.PlanInput {
	documents := func(value any) []any {
		list, _ := value.([]any)
		return list
	}
	input := core.PlanInput{
		Action:       str(o, "action"),
		ResourceType: str(o, "resourceType"),
		TenantID:     str(o, "tenantId"),
		Context:      obj(o, "context"),
		Denies:       documents(o.Get("denies")),
		Boundaries:   documents(o.Get("boundaries")),
	}
	for _, item := range documents(o.Get("paths")) {
		path := item.(*core.Object)
		input.Paths = append(input.Paths, core.PlanPath{Grants: documents(path.Get("grants")), Boundaries: documents(path.Get("boundaries"))})
	}
	for _, item := range documents(o.Get("relations")) {
		relation := item.(*core.Object)
		var names []string
		for _, name := range documents(relation.Get("relations")) {
			names = append(names, name.(string))
		}
		input.Relations = append(input.Relations, core.PlanRelation{Type: str(relation, "type"), ID: str(relation, "id"), Relations: names})
	}
	if mandatory := o.Get("mandatory"); !core.IsUndefined(mandatory) {
		filter := filterOf(t, mandatory)
		input.Mandatory = &filter
	}
	for _, key := range documents(o.Get("derivedResourceKeys")) {
		input.DerivedResourceKeys = append(input.DerivedResourceKeys, key.(string))
	}
	return input
}

func TestPlanVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "plan").Cases {
		name := strings.SplitN(c.Name, " ", 2)[0]
		switch name {
		case "andFilter":
			spectest.Check(t, c, spectest.Model(core.AndFilter(filtersOf(t, c.Input.Get("filters")))))
		case "orFilter":
			spectest.Check(t, c, spectest.Model(core.OrFilter(filtersOf(t, c.Input.Get("filters")))))
		case "notFilter":
			spectest.Check(t, c, spectest.Model(core.NotFilter(filterOf(t, c.Input.Get("filter")))))
		case "parseGlob":
			spectest.Check(t, c, spectest.Model(core.ParseGlob(str(c.Input, "pattern"))))
		case "globMatches":
			spectest.Check(t, c, core.GlobMatches(core.ParseGlob(str(c.Input, "pattern")), str(c.Input, "value")))
		case "fixedPlan":
			allowed, _ := c.Input.Bool("allowed")
			spectest.Check(t, c, spectest.Model(core.FixedPlan(allowed)))
		case "intersectPlans":
			spectest.Check(t, c, spectest.Model(core.IntersectPlans(planOf(t, c.Input.Get("left")), planOf(t, c.Input.Get("right")))))
		default:
			plan, err := core.PlanResources(planInput(t, c.Input))
			spectest.Check(t, c, spectest.Outcome(plan, err))
		}
	}
}

func sqlColumn(field string) string {
	if strings.HasPrefix(field, "missing") {
		return ""
	}
	return `"` + field + `"`
}

// mongoModel renders RegExp values as the vectors do (a RegExp has no own enumerable properties: {}).
func mongoModel(value any) any {
	switch v := value.(type) {
	case *core.Object:
		if v == nil {
			return v
		}
		out := core.NewObject()
		v.Entries(func(key string, item any) bool {
			out.SetRaw(key, mongoModel(item))
			return true
		})
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = mongoModel(item)
		}
		return out
	case core.RegExp:
		return core.NewObject()
	}
	return value
}

func TestFilterCompilerVectors(t *testing.T) {
	regexps := 0
	for _, c := range spectest.Load(t, "filter-compilers").Cases {
		filter := filterOf(t, c.Input.Get("filter"))
		switch {
		case c.Name == "postgres with offset":
			offset, _ := c.Input.Number("offset")
			result, err := core.FilterToSql(filter, core.SqlFilterOptions{Dialect: "postgres", Column: sqlColumn, Offset: int(offset)})
			spectest.Check(t, c, spectest.Outcome(result, err))
		case c.Name == "prisma with field mapping":
			result, err := core.FilterToPrisma(filter, core.PrismaFilterOptions{Field: func(field string) string {
				if field == "id" {
					return "uid"
				}
				return "attr_" + field
			}})
			spectest.Check(t, c, spectest.Outcome(result, err))
		case c.Name == "mongo with field mapping":
			result, err := core.FilterToMongo(filter, core.MongoFilterOptions{Field: func(field string) string {
				if field == "id" {
					return "_id"
				}
				return field
			}})
			spectest.Check(t, c, spectest.Outcome(mongoModel(result), err))
		case strings.HasPrefix(c.Name, "sqlite "), strings.HasPrefix(c.Name, "postgres "):
			result, err := core.FilterToSql(filter, core.SqlFilterOptions{Dialect: str(c.Input, "dialect"), Column: sqlColumn})
			spectest.Check(t, c, spectest.Outcome(result, err))
		case strings.HasPrefix(c.Name, "prisma "):
			result, err := core.FilterToPrisma(filter, core.PrismaFilterOptions{})
			spectest.Check(t, c, spectest.Outcome(result, err))
		case strings.HasPrefix(c.Name, "mongo "):
			result, err := core.FilterToMongo(filter, core.MongoFilterOptions{})
			if c.Name == "mongo equals ignore case" && err == nil {
				// The vector shows RegExp values as {}; check the expressions themselves here.
				values, _ := obj(result, "team").Get("$in").([]any)
				if len(values) != 3 || values[0] != (core.RegExp{Source: "^Eng$", Flags: "iu"}) || values[1] != (core.RegExp{Source: "^OPS$", Flags: "iu"}) {
					t.Errorf("mongo equals ignore case: unexpected regular expressions %#v", values)
				}
				regexps++
			}
			spectest.Check(t, c, spectest.Outcome(mongoModel(result), err))
		case strings.HasPrefix(c.Name, "describe "):
			spectest.Check(t, c, core.DescribeFilter(filter))
		case strings.HasPrefix(c.Name, "matches "):
			spectest.Check(t, c, core.FilterMatches(filter, obj(c.Input, "record")))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
	if regexps != 1 {
		t.Errorf("expected the mongo equals ignore case vector")
	}
}

func capabilitiesOf(value any) core.QueryCapabilities {
	o, _ := value.(*core.Object)
	if o == nil {
		return core.QueryCapabilities{}
	}
	json, _ := o.Bool("json")
	order, _ := o.Bool("order")
	return core.QueryCapabilities{JSON: json, Order: order}
}

func TestStorageVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "storage").Cases {
		switch strings.SplitN(c.Name, " ", 2)[0] {
		case "planQuery":
			plan := core.PlanQuery(str(c.Input, "collection"), obj(c.Input, "filter"), capabilitiesOf(c.Input.Get("capabilities")))
			spectest.Check(t, c, spectest.Model(plan))
		case "matchesFilter":
			spectest.Check(t, c, core.MatchesFilter(obj(c.Input, "record"), obj(c.Input, "filter")))
		case "compareIds":
			result := core.CompareIDs(str(c.Input, "a"), str(c.Input, "b"))
			sign := 0.0
			if result < 0 {
				sign = -1
			} else if result > 0 {
				sign = 1
			}
			spectest.Check(t, c, sign)
		case "storableString":
			spectest.Check(t, c, core.StorableString(str(c.Input, "value")))
		case "encodeJsonbDocument":
			spectest.Check(t, c, spectest.Outcome(core.EncodeJSONBDocument(str(c.Input, "data"))))
		case "decodeJsonbDocument":
			spectest.Check(t, c, spectest.Outcome(core.DecodeJSONBDocument(str(c.Input, "data"))))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func optionalNumber(o *core.Object, key string) *float64 {
	if value, ok := o.Number(key); ok {
		return &value
	}
	return nil
}

func optionalInt(o *core.Object, key string) *int {
	if value, ok := o.Number(key); ok {
		n := int(value)
		return &n
	}
	return nil
}

// queryOf reads a RecordQuery written as a model value.
func queryOf(o *core.Object) core.RecordQuery {
	query := core.RecordQuery{Collection: str(o, "collection")}
	for _, item := range objects(o.Get("conditions")) {
		query.Conditions = append(query.Conditions, core.FieldCondition{Field: str(item, "field"), Kind: str(item, "kind"), Value: item.Get("value")})
	}
	return query
}

func TestSQLVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "sql").Cases {
		if c.Input.Has("query") {
			statement, err := core.SqliteSelect(queryOf(obj(c.Input, "query")))
			spectest.Check(t, c, spectest.Outcome(statement, err))
			continue
		}
		dialect := strings.SplitN(c.Name, " ", 2)[0]
		capabilities := core.QueryCapabilities{Order: true, JSON: dialect == "postgres"}
		if c.Input.Has("capabilities") {
			capabilities = capabilitiesOf(c.Input.Get("capabilities"))
		}
		plan := core.PlanQuery(str(c.Input, "collection"), obj(c.Input, "filter"), capabilities)
		query := plan.Query
		if after, ok := c.Input.String("after"); ok {
			query.After = &after
		}
		if order, ok := c.Input.Object("order"); ok {
			query.Order = &core.QueryOrder{Field: str(order, "field"), Direction: str(order, "direction"), From: optionalNumber(order, "from"), To: optionalNumber(order, "to")}
		}
		if page, ok := c.Input.Object("page"); ok {
			offset, _ := page.Number("offset")
			query.Page = &core.QueryPage{Offset: int(offset), Limit: optionalInt(page, "limit")}
		}
		var statement core.SqlStatement
		var err error
		if dialect == "postgres" {
			statement, err = core.PostgresSelect(query)
		} else {
			statement, err = core.SqliteSelect(query)
		}
		if err != nil {
			spectest.Check(t, c, spectest.ErrorValue(err))
			continue
		}
		spectest.Check(t, c, core.NewObject("query", spectest.Model(query), "exact", plan.Exact, "statement", spectest.Model(statement)))
	}
}

func subjectOutcome(subject *core.SubjectIdentifier) any {
	if subject == nil {
		return core.Undefined
	}
	return subject.ToValue()
}

func TestSharedSignalVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "shared-signals").Cases {
		switch strings.SplitN(c.Name, " ", 2)[0] {
		case "signalEventType":
			spectest.Check(t, c, core.SignalEventTypeOf(str(c.Input, "uri")))
		case "parseSubjectIdentifier":
			spectest.Check(t, c, subjectOutcome(core.ParseSubjectIdentifier(c.Input.Get("value"))))
		case "legacyRiscSubject":
			spectest.Check(t, c, subjectOutcome(core.LegacyRiscSubject(c.Input.Get("value"))))
		case "readSecurityEvent":
			claims, err := core.ReadSecurityEvent(c.Input.Get("payload"))
			if err != nil {
				spectest.Check(t, c, spectest.ErrorValue(err))
			} else {
				spectest.Check(t, c, claims.ToValue())
			}
		case "userSubjects":
			var subject *core.SubjectIdentifier
			if value := c.Input.Get("subject"); !core.IsUndefined(value) {
				subject = core.ParseSubjectIdentifier(value)
				if subject == nil {
					t.Fatalf("%s: subject did not parse", c.Name)
				}
			}
			list := []any{}
			for _, item := range core.UserSubjects(subject) {
				list = append(list, item.ToValue())
			}
			spectest.Check(t, c, list)
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func schemeOf(t *testing.T, value any) *core.ClassificationSchemeDefinition {
	t.Helper()
	var scheme core.ClassificationSchemeDefinition
	if err := core.FromRecord(value, &scheme); err != nil {
		t.Fatal(err)
	}
	return &scheme
}

func labelOutcome(value any) any {
	switch v := value.(type) {
	case nil:
		return core.Undefined
	case *core.ClassificationLabel:
		return v.ToValue()
	}
	return value
}

func partyOf(value any) *core.ClearanceParty {
	o := value.(*core.Object)
	party := &core.ClearanceParty{IdentityID: str(o, "identityId"), Compartments: map[string]bool{}, Citizenship: map[string]bool{}}
	party.Rank, _ = o.Number("rank")
	for _, key := range []string{"compartments", "citizenship"} {
		members, _ := o.Get(key).(spectest.Set)
		for _, member := range members {
			if key == "compartments" {
				party.Compartments[member.(string)] = true
			} else {
				party.Citizenship[member.(string)] = true
			}
		}
	}
	return party
}

func TestClassificationVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "classification").Cases {
		name := strings.SplitN(c.Name, " ", 2)[0]
		var scheme *core.ClassificationSchemeDefinition
		if value := c.Input.Get("scheme"); name != "validateScheme" && !core.IsUndefined(value) {
			scheme = schemeOf(t, value)
		}
		switch name {
		case "template":
			spectest.Check(t, c, spectest.Model(core.ClassificationTemplates[str(c.Input, "name")]))
		case "validateScheme":
			result, err := core.ValidateScheme(c.Input.Get("scheme"))
			spectest.Check(t, c, spectest.Outcome(result, err))
		case "validateLabel":
			label, err := core.ValidateLabel(c.Input.Get("label"), scheme)
			if err != nil {
				spectest.Check(t, c, spectest.ErrorValue(err))
			} else {
				spectest.Check(t, c, label.ToValue())
			}
		case "isValidClassificationLabel":
			spectest.Check(t, c, core.IsValidClassificationLabel(c.Input.Get("label"), scheme))
		case "labelRank":
			spectest.Check(t, c, undefinedOr(core.LabelRank(c.Input.Get("label"), scheme)))
		case "joinLabels":
			spectest.Check(t, c, labelOutcome(core.JoinLabels(c.Input.Get("a"), c.Input.Get("b"), scheme)))
		case "dominates":
			failure := core.Dominates(partyOf(c.Input.Get("party")), c.Input.Get("label"), scheme)
			if failure == "" {
				spectest.Check(t, c, nil)
			} else {
				spectest.Check(t, c, failure)
			}
		case "labelCovers":
			spectest.Check(t, c, core.LabelCovers(c.Input.Get("upper"), c.Input.Get("lower"), scheme))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func TestDelegationTokenVectors(t *testing.T) {
	ran := 0
	for _, c := range spectest.Load(t, "delegation-tokens").Cases {
		switch strings.SplitN(c.Name, " ", 2)[0] {
		case "read":
			expected := obj(c.Input, "expected")
			expectations := core.DelegationTokenExpectations{Audience: str(expected, "audience")}
			switch issuer := expected.Get("issuer").(type) {
			case string:
				expectations.Issuers = []string{issuer}
			case []any:
				for _, item := range issuer {
					expectations.Issuers = append(expectations.Issuers, item.(string))
				}
			}
			if tenant, ok := expected.String("tenantId"); ok {
				expectations.TenantID = &tenant
			}
			expectations.Now, _ = expected.Number("now")
			expectations.ClockToleranceSeconds = optionalNumber(expected, "clockToleranceSeconds")
			result, err := core.ReadDelegationTokenClaims(c.Input.Get("claims"), expectations)
			if err != nil {
				spectest.Check(t, c, spectest.ErrorValue(err))
			} else {
				spectest.Check(t, c, spectest.Model(result.ToValue()))
			}
			ran++
		case "delegationActor":
			list, _ := c.Input.Get("chain").([]any)
			chain := make([]string, len(list))
			for index, item := range list {
				chain[index] = item.(string)
			}
			actor, err := core.NewDelegationActor(chain)
			spectest.Check(t, c, spectest.Outcome(actor, err))
			ran++
		default:
			// sign / verify / server verifyJwt cases belong to the server and a2a ports (EdDSA signing).
		}
	}
	if ran != 31 {
		t.Errorf("expected 31 core delegation token cases, ran %d", ran)
	}
}
