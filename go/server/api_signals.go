package server

// Port of packages/server/src/api/signals.ts: the `signals` group, the tenant's Shared Signals sources (upstream
// identity providers that send CAEP and RISC security events about its people) and the events they sent. Reading
// needs `iam:signals:read`, everything else `iam:signals:manage` on `iam/signals/sources[/{id}]` or
// `iam/signals/events[/{id}]`; changes need recent authentication. Events arrive through the push endpoint or
// `iam.signals.poll()`, never through this group.

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strconv"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func signalSourceResource(sourceID string) string { return "signals/sources/" + sourceID }
func signalEventResource(eventID string) string   { return "signals/events/" + eventID }

var (
	signalDeliveries     = map[string]bool{"push": true, "poll": true}
	signalStatuses       = map[string]bool{"applied": true, "recorded": true, "unmatched": true, "ignored": true, "failed": true}
	signalSourceStatuses = map[string]bool{"active": true, "disabled": true}
	signalActionValues   = map[string]bool{"record": true, "revoke-sessions": true}
	signalKnownEvents    = func() map[string]bool {
		known := map[string]bool{"unknown": true}
		for _, eventType := range core.SignalEventTypes {
			known[eventType] = true
		}
		return known
	}()
	signalActionableEvents = func() map[string]bool {
		actionable := map[string]bool{}
		for _, eventType := range core.SignalEventTypes {
			if eventType != "verification" && eventType != "stream-updated" {
				actionable[eventType] = true
			}
		}
		return actionable
	}()
	signalUpdatableFields = []string{
		"name", "issuerAliases", "audiences", "jwksUri", "jwks", "algorithms", "poll", "subjects", "actions",
		"requireTyp", "tenantClaim", "status",
	}
	// signalBearerToken is printable ASCII without spaces: what a bearer token may contain.
	signalBearerToken = regexp.MustCompile(`^[!-~]+$`)
)

func signalBoolean(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return flag, nil
}

// signalIssuerKey is the source's natural key within its tenant, `issuer:{issuer}`; an issuer too long for the 512-byte
// key limit is keyed by its SHA-256 instead.
func signalIssuerKey(issuer string) string {
	key := "issuer:" + issuer
	if len(key) <= 512 {
		return key
	}
	return "issuer#sha256:" + Hash(issuer)
}

func signalIdentifierList(value any, name string) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) > 10 {
		return nil, invalidInput(name + " must list at most 10 ids")
	}
	ids := make([]string, 0, len(list))
	for _, entry := range list {
		text, err := Text(entry, name, 128)
		if err != nil {
			return nil, err
		}
		ids = append(ids, core.JSTrim(text))
	}
	return stringsOf(unique(ids)), nil
}

func signalSubjectsValue(value any, current *core.Object) (*core.Object, error) {
	base := core.NewObject("connectionIds", []any{}, "matchEmail", false, "scimConnectionIds", []any{})
	if current != nil {
		base = core.NewObject(
			"connectionIds", core.CloneValue(current.Get("connectionIds")),
			"matchEmail", current.Get("matchEmail"),
			"scimConnectionIds", core.CloneValue(current.Get("scimConnectionIds")),
		)
	}
	if isUndefined(value) {
		return base, nil
	}
	input, ok := value.(*core.Object)
	if !ok || input == nil {
		return nil, invalidInput("subjects must be an object")
	}
	for _, key := range input.Keys() {
		if key != "connectionIds" && key != "matchEmail" && key != "scimConnectionIds" {
			return nil, invalidInput("Unknown subjects member " + key)
		}
	}
	if ids := input.Get("connectionIds"); !isUndefined(ids) {
		list, err := signalIdentifierList(ids, "subjects.connectionIds")
		if err != nil {
			return nil, err
		}
		base.Set("connectionIds", list)
	}
	if ids := input.Get("scimConnectionIds"); !isUndefined(ids) {
		list, err := signalIdentifierList(ids, "subjects.scimConnectionIds")
		if err != nil {
			return nil, err
		}
		base.Set("scimConnectionIds", list)
	}
	if match := input.Get("matchEmail"); !isUndefined(match) {
		flag, err := signalBoolean(match, "subjects.matchEmail")
		if err != nil {
			return nil, err
		}
		base.Set("matchEmail", flag)
	}
	return base, nil
}

func signalActionsValue(value any) (*core.Object, error) {
	input, ok := value.(*core.Object)
	if !ok || input == nil {
		return nil, invalidInput("actions must map event types to record or revoke-sessions")
	}
	result := core.NewObject()
	var failure error
	input.Entries(func(eventType string, action any) bool {
		if !signalActionableEvents[eventType] {
			failure = invalidInput("actions names an unsupported event type: " + eventType)
			return false
		}
		if text, isText := action.(string); !isText || !signalActionValues[text] {
			failure = invalidInput("The action for " + eventType + " must be record or revoke-sessions")
			return false
		}
		result.Set(eventType, action)
		return true
	})
	if failure != nil {
		return nil, failure
	}
	return result, nil
}

// publicSignalSource is the `signals` view of a source: an explicit allowlist without the token hash and the sealed
// poll token.
func publicSignalSource(server *ServerContext, source *core.Object) *core.Object {
	subjects := signalSubjects(source)
	view := core.NewObject(
		"id", source.Get("id"),
		"tenantId", source.Get("tenantId"),
		"name", source.Get("name"),
		"issuer", source.Get("issuer"),
		"issuerAliases", core.CloneValue(source.Get("issuerAliases")),
		"audiences", core.CloneValue(source.Get("audiences")),
		"algorithms", core.CloneValue(source.Get("algorithms")),
		"delivery", source.Get("delivery"),
		"hasPushToken", !isUndefined(source.Get("pushTokenHash")),
		"subjects", core.NewObject(
			"connectionIds", core.CloneValue(subjects.Get("connectionIds")),
			"matchEmail", subjects.Get("matchEmail") == true,
			"scimConnectionIds", core.CloneValue(subjects.Get("scimConnectionIds")),
		),
		"actions", core.CloneValue(coalesce(source.Get("actions"), core.NewObject())),
		"requireTyp", source.Get("requireTyp") != false,
		"status", source.Get("status"),
		"createdAt", source.Get("createdAt"),
		"createdBy", source.Get("createdBy"),
		"updatedAt", source.Get("updatedAt"),
		"updatedBy", source.Get("updatedBy"),
	)
	if source.Get("delivery") == "push" {
		view.Set("pushUrl", server.Config.BaseOrigin()+server.Config.Signals.PushPath+"/"+jsString(source.Get("id")))
	}
	if jwksURI := source.Get("jwksUri"); !isUndefined(jwksURI) {
		view.Set("jwksUri", jwksURI)
	}
	if jwks := source.Get("jwks"); !isUndefined(jwks) {
		view.Set("jwks", core.CloneValue(jwks))
	}
	if tenantClaim := source.Get("tenantClaim"); !isUndefined(tenantClaim) {
		view.Set("tenantClaim", tenantClaim)
	}
	if poll, ok := source.Get("poll").(*core.Object); ok && poll != nil {
		pending, _ := poll.Get("pendingAcks").([]any)
		state := core.NewObject(
			"endpoint", poll.Get("endpoint"),
			"maxEvents", poll.Get("maxEvents"),
			"pendingAcks", float64(len(pending)),
		)
		if lastPolledAt := poll.Get("lastPolledAt"); !isUndefined(lastPolledAt) {
			state.Set("lastPolledAt", lastPolledAt)
		}
		view.Set("poll", state)
	}
	if lastEventAt := source.Get("lastEventAt"); !isUndefined(lastEventAt) {
		view.Set("lastEventAt", lastEventAt)
	}
	if lastError := source.Get("lastError"); !isUndefined(lastError) {
		view.Set("lastError", core.CloneValue(lastError))
	}
	if lastVerifiedAt := source.Get("lastVerifiedAt"); !isUndefined(lastVerifiedAt) {
		view.Set("lastVerifiedAt", lastVerifiedAt)
	}
	return view
}

func publicSignalEvent(record *core.Object) *core.Object {
	view := core.NewObject(
		"id", record.Get("id"),
		"tenantId", record.Get("tenantId"),
		"sourceId", record.Get("sourceId"),
		"jti", record.Get("jti"),
		"eventType", record.Get("eventType"),
		"eventUri", record.Get("eventUri"),
		"issuedAt", record.Get("issuedAt"),
		"status", record.Get("status"),
		"claims", core.CloneValue(record.Get("claims")),
		"receivedAt", record.Get("receivedAt"),
		"expiresAt", record.Get("expiresAt"),
	)
	for _, name := range []string{"eventTimestamp", "txn", "subject", "identityId", "reason", "reprocessedAt", "reprocessedBy"} {
		if value := record.Get(name); !isUndefined(value) {
			view.Set(name, core.CloneValue(value))
		}
	}
	return view
}

// SignalsAPI is the `signals` API group (packages/server/src/api/signals.ts createSignalsApi): every method runs
// through the operation envelope; the router maps POST {basePath}/signals/{method} onto it.
type SignalsAPI struct {
	server       *ServerContext
	addressRules auth.SafeFetchAddressOptions
}

// CreateSignalsAPI builds the `signals` API group.
func CreateSignalsAPI(server *ServerContext) *SignalsAPI {
	settings := server.Config.Signals
	return &SignalsAPI{server: server, addressRules: auth.SafeFetchAddressOptions{
		AnyPort: true, AllowPrivateNetworks: settings.AllowPrivateNetworks, AllowInsecureLocalhost: settings.AllowInsecureLocalhost,
	}}
}

// issuerValue is an issuer: https (loopback http in development), no credentials, query or fragment; trailing
// slashes dropped.
func (api *SignalsAPI) issuerValue(value any) (string, error) {
	issuer, err := WebIdentityIssuer(value, WebIdentityIssuerOptions{AllowInsecureLocalhost: api.server.Config.Signals.AllowInsecureLocalhost})
	if err != nil {
		return "", err
	}
	return signalTrimSlashes(issuer), nil
}

func (api *SignalsAPI) aliasesValue(value any, issuer string) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) > 5 {
		return nil, invalidInput("issuerAliases must list at most 5 issuers")
	}
	aliases := make([]string, 0, len(list))
	for _, alias := range list {
		checked, err := api.issuerValue(alias)
		if err != nil {
			if known, ok := asIamError(err); ok {
				return nil, invalidInput("issuerAliases: " + known.Message)
			}
			return nil, err
		}
		aliases = append(aliases, checked)
	}
	result := []any{}
	for _, alias := range unique(aliases) {
		if alias != issuer {
			result = append(result, alias)
		}
	}
	return result, nil
}

// urlValue is a URL the receiver fetches: https on any port (loopback http in development) and a public address.
func (api *SignalsAPI) urlValue(value any, name string) (string, error) {
	raw, err := Text(value, name, 2048)
	if err != nil {
		return "", err
	}
	if _, err := auth.CheckFetchURL(raw, api.addressRules); err != nil {
		var refused *auth.SafeFetchError
		if errors.As(err, &refused) && refused.Reason == "address" {
			return "", invalidInput(name + " must not point at a private address")
		}
		return "", invalidInput(name + " must be an https URL without credentials or a fragment")
	}
	return raw, nil
}

func signalPollTokenValue(value any) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" || utf16Len(text) > 4096 || !signalBearerToken.MatchString(text) {
		return "", invalidInput("poll.token must be 1 to 4096 printable characters without spaces")
	}
	return text, nil
}

func signalMaxEventsValue(value any) (float64, error) {
	return Integer(value, "poll.maxEvents", 1, 100)
}

func signalPollObject(value any) (*core.Object, error) {
	poll, ok := value.(*core.Object)
	if !ok || poll == nil {
		return nil, invalidInput("poll must be an object with endpoint, token and maxEvents")
	}
	for _, key := range poll.Keys() {
		if key != "endpoint" && key != "token" && key != "maxEvents" {
			return nil, invalidInput("Unknown poll member " + key)
		}
	}
	return poll, nil
}

// scopedSource is a source of this tenant, else NOT_FOUND.
func (api *SignalsAPI) scopedSource(ctx context.Context, tx core.IamStore, tenantID any, sourceID string) (*core.Object, error) {
	return api.server.Scoped(ctx, tx, SignalCollections.Sources, sourceID, jsString(tenantID))
}

func (api *SignalsAPI) forget(sourceID string) { _ = SignalReceiverOf(api.server).Forget(sourceID) }

// CreateSource is POST {basePath}/signals/createSource. Registers a transmitter (iam:signals:manage on
// iam/signals/sources, recent authentication), at most 20 per tenant and one per issuer (CONFLICT). Push sources get a
// push URL and, unless `pushToken: false`, a bearer token returned only here; poll sources store their poll token
// sealed. Static keys must be public signature keys; URLs must be https and public (see the `signals` deployment
// option). Nothing is fetched now. Audited as `signal:source-create`.
func (api *SignalsAPI) CreateSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsCreateSourceInput]) (Out[apitypes.SignalsCreateSourceOutput], error) {
	fail := func(err error) (Out[apitypes.SignalsCreateSourceOutput], error) {
		return Out[apitypes.SignalsCreateSourceOutput]{}, err
	}
	server := api.server
	rawName, err := Text(input.Get("name"), "name", 128)
	if err != nil {
		return fail(err)
	}
	name := core.JSTrim(rawName)
	issuer, err := api.issuerValue(input.Get("issuer"))
	if err != nil {
		return fail(err)
	}
	issuerAliases := []any{}
	if value := input.Get("issuerAliases"); !isUndefined(value) {
		if issuerAliases, err = api.aliasesValue(value, issuer); err != nil {
			return fail(err)
		}
	}
	audiences, err := WebIdentityAudiences(input.Get("audiences"))
	if err != nil {
		return fail(err)
	}
	jwksURI := ""
	hasJwksURI := !isUndefined(input.Get("jwksUri"))
	if hasJwksURI {
		if jwksURI, err = api.urlValue(input.Get("jwksUri"), "jwksUri"); err != nil {
			return fail(err)
		}
	}
	var jwks *core.Object
	if value := input.Get("jwks"); !isUndefined(value) {
		if jwks, err = WebIdentityKeys(value); err != nil {
			return fail(err)
		}
	}
	if hasJwksURI && jwks != nil {
		return fail(invalidInput("Give jwks or jwksUri, not both"))
	}
	algorithms := append([]string{}, DefaultSignalAlgorithms...)
	if value := input.Get("algorithms"); !isUndefined(value) {
		if algorithms, err = WebIdentityWebIdentityAlgorithms(value); err != nil {
			return fail(err)
		}
	}
	delivery, _ := input.Get("delivery").(string)
	if !signalDeliveries[delivery] {
		return fail(invalidInput("delivery must be push or poll"))
	}
	wantsPushToken := delivery == "push"
	if value := input.Get("pushToken"); !isUndefined(value) {
		if wantsPushToken, err = signalBoolean(value, "pushToken"); err != nil {
			return fail(err)
		}
	}
	if delivery == "poll" && wantsPushToken {
		return fail(invalidInput("Poll sources receive no pushes, so they take no push token"))
	}
	var pollEndpoint, pollToken string
	pollMaxEvents := 25.0
	if delivery == "poll" {
		if isUndefined(input.Get("poll")) {
			return fail(invalidInput("Poll sources need poll.endpoint and poll.token"))
		}
		given, err := signalPollObject(input.Get("poll"))
		if err != nil {
			return fail(err)
		}
		if pollEndpoint, err = api.urlValue(given.Get("endpoint"), "poll.endpoint"); err != nil {
			return fail(err)
		}
		if pollToken, err = signalPollTokenValue(given.Get("token")); err != nil {
			return fail(err)
		}
		if value := given.Get("maxEvents"); !isUndefined(value) {
			if pollMaxEvents, err = signalMaxEventsValue(value); err != nil {
				return fail(err)
			}
		}
	} else if !isUndefined(input.Get("poll")) {
		return fail(invalidInput("Only poll sources take poll settings"))
	}
	subjects, err := signalSubjectsValue(input.Get("subjects"), nil)
	if err != nil {
		return fail(err)
	}
	actions := core.NewObject()
	if value := input.Get("actions"); !isUndefined(value) {
		if actions, err = signalActionsValue(value); err != nil {
			return fail(err)
		}
	}
	requireTyp := true
	if value := input.Get("requireTyp"); !isUndefined(value) {
		if requireTyp, err = signalBoolean(value, "requireTyp"); err != nil {
			return fail(err)
		}
	}
	tenantClaim := ""
	hasTenantClaim := !isUndefined(input.Get("tenantClaim"))
	if hasTenantClaim {
		claim, err := Text(input.Get("tenantClaim"), "tenantClaim")
		if err != nil {
			return fail(err)
		}
		tenantClaim = core.JSTrim(claim)
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", "signals/sources", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, SignalCollections.Sources, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) >= MaxSignalSourcesPerTenant {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant may register at most "+strconv.Itoa(MaxSignalSourcesPerTenant)+" signal sources", 409)
		}
		uniqueKey := signalIssuerKey(issuer)
		for _, source := range existing {
			if source.Get("uniqueKey") == uniqueKey {
				return nil, core.NewIamError("CONFLICT", "A signal source for this issuer already exists", 409)
			}
		}
		now := float64(server.Now())
		sourceID := ID()
		pushToken := ""
		if wantsPushToken {
			pushToken = Token()
		}
		source := core.NewObject(
			"id", sourceID,
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"name", name,
			"issuer", issuer,
			"issuerAliases", issuerAliases,
			"audiences", stringsOf(audiences),
		)
		if hasJwksURI {
			source.Set("jwksUri", jwksURI)
		}
		if jwks != nil {
			source.Set("jwks", jwks)
		}
		source.Set("algorithms", stringsOf(algorithms))
		source.Set("delivery", delivery)
		if pushToken != "" {
			source.Set("pushTokenHash", Hash(pushToken))
		}
		if delivery == "poll" {
			sealed, err := SealPollToken(server, sourceID, pollToken)
			if err != nil {
				return nil, err
			}
			source.Set("poll", core.NewObject(
				"endpoint", pollEndpoint,
				"tokenSealed", sealed,
				"maxEvents", pollMaxEvents,
				"pendingAcks", []any{},
			))
		}
		source.Set("subjects", subjects)
		source.Set("actions", actions)
		source.Set("requireTyp", requireTyp)
		if hasTenantClaim {
			source.Set("tenantClaim", tenantClaim)
		}
		source.Set("status", "active")
		source.Set("createdAt", now)
		source.Set("createdBy", principal.Identity.Get("id"))
		source.Set("updatedAt", now)
		source.Set("updatedBy", principal.Identity.Get("id"))
		if _, err := tx.Insert(ctx, SignalCollections.Sources, source); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "signal:source-create", jsString(tenantID), signalSourceResource(sourceID),
			"allow", false, core.NewObject("name", name, "issuer", issuer, "delivery", delivery)); err != nil {
			return nil, err
		}
		view := publicSignalSource(server, source)
		created := core.NewObject("source", view)
		if pushURL := view.Get("pushUrl"); !isUndefined(pushURL) {
			created.Set("pushUrl", pushURL)
		}
		if pushToken != "" {
			created.Set("pushToken", pushToken)
		}
		return created, nil
	}, false)
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.SignalsCreateSourceOutput]{Value: result}, nil
}

// DeleteSource is POST {basePath}/signals/deleteSource. Deletes a source (iam:signals:manage on
// iam/signals/sources/{id}, recent authentication). Its pushes answer 404 from now on; the events it sent stay until
// the retention sweep removes them. Audited as `signal:source-delete`.
func (api *SignalsAPI) DeleteSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsDeleteSourceInput]) (Out[apitypes.SignalsDeleteSourceOutput], error) {
	server := api.server
	sourceID, err := Text(input.Get("sourceId"), "sourceId")
	if err != nil {
		return Out[apitypes.SignalsDeleteSourceOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", signalSourceResource(sourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		source, err := api.scopedSource(ctx, tx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, SignalCollections.Sources, jsString(source.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "signal:source-delete", jsString(tenantID), signalSourceResource(jsString(source.Get("id"))),
			"allow", false, core.NewObject("name", source.Get("name"), "issuer", source.Get("issuer"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsDeleteSourceOutput]{}, err
	}
	api.forget(sourceID)
	return Out[apitypes.SignalsDeleteSourceOutput]{Value: result}, nil
}

// GetEvent is POST {basePath}/signals/getEvent. One received event (iam:signals:read on iam/signals/events/{id}).
func (api *SignalsAPI) GetEvent(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsGetEventInput]) (Out[apitypes.SignalsGetEventOutput], error) {
	server := api.server
	eventID, err := Text(input.Get("eventId"), "eventId")
	if err != nil {
		return Out[apitypes.SignalsGetEventOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:read", signalEventResource(eventID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		record, err := server.Scoped(ctx, call.Tx, SignalCollections.Events, eventID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return publicSignalEvent(record), nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsGetEventOutput]{}, err
	}
	return Out[apitypes.SignalsGetEventOutput]{Value: result}, nil
}

// GetSource is POST {basePath}/signals/getSource. One signal source (iam:signals:read on iam/signals/sources/{id}).
func (api *SignalsAPI) GetSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsGetSourceInput]) (Out[apitypes.SignalsGetSourceOutput], error) {
	server := api.server
	sourceID, err := Text(input.Get("sourceId"), "sourceId")
	if err != nil {
		return Out[apitypes.SignalsGetSourceOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:read", signalSourceResource(sourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		source, err := api.scopedSource(ctx, call.Tx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		return publicSignalSource(server, source), nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsGetSourceOutput]{}, err
	}
	return Out[apitypes.SignalsGetSourceOutput]{Value: result}, nil
}

// ListEvents is POST {basePath}/signals/listEvents. Received events, newest first, optionally of one source, status,
// identity or event type (iam:signals:read on iam/signals/events). `limit` 1..1000 (default 100), `offset` from 0.
func (api *SignalsAPI) ListEvents(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsListEventsInput]) (Out[apitypes.SignalsListEventsOutput], error) {
	fail := func(err error) (Out[apitypes.SignalsListEventsOutput], error) {
		return Out[apitypes.SignalsListEventsOutput]{}, err
	}
	server := api.server
	limitValue := input.Get("limit")
	if nullish(limitValue) {
		limitValue = 100.0
	}
	limit, err := Integer(limitValue, "limit", 1, 1000)
	if err != nil {
		return fail(err)
	}
	offsetValue := input.Get("offset")
	if nullish(offsetValue) {
		offsetValue = 0.0
	}
	offset, err := Integer(offsetValue, "offset", 0, 1_000_000)
	if err != nil {
		return fail(err)
	}
	sourceID, hasSource := "", !isUndefined(input.Get("sourceId"))
	if hasSource {
		if sourceID, err = Text(input.Get("sourceId"), "sourceId"); err != nil {
			return fail(err)
		}
	}
	identityID, hasIdentity := "", !isUndefined(input.Get("identityId"))
	if hasIdentity {
		if identityID, err = Text(input.Get("identityId"), "identityId"); err != nil {
			return fail(err)
		}
	}
	status := input.Get("status")
	if !isUndefined(status) {
		if text, ok := status.(string); !ok || !signalStatuses[text] {
			return fail(invalidInput("status must be applied, recorded, unmatched, ignored or failed"))
		}
	}
	eventType := input.Get("eventType")
	if !isUndefined(eventType) {
		if text, ok := eventType.(string); !ok || !signalKnownEvents[text] {
			return fail(invalidInput("Unknown eventType"))
		}
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:read", "signals/events", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		filter := core.NewObject("tenantId", tenantID)
		if hasSource {
			filter.Set("streamId", sourceID)
		}
		if !isUndefined(status) {
			filter.Set("status", status)
		}
		if hasIdentity {
			filter.Set("identityId", identityID)
		}
		if !isUndefined(eventType) {
			filter.Set("eventType", eventType)
		}
		events, err := core.FindOrdered(ctx, call.Tx, SignalCollections.Events, filter, core.OrderOptions{Field: "timestamp", Direction: "desc"}, nil)
		if err != nil {
			return nil, err
		}
		start, end := int(offset), int(offset+limit)
		if start > len(events) {
			start = len(events)
		}
		if end > len(events) {
			end = len(events)
		}
		page := make([]any, 0, end-start)
		for _, record := range events[start:end] {
			page = append(page, publicSignalEvent(record))
		}
		return core.NewObject("events", page, "total", float64(len(events))), nil
	}, false)
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.SignalsListEventsOutput]{Value: result}, nil
}

// ListSources is POST {basePath}/signals/listSources. The tenant's signal sources, oldest first (iam:signals:read on
// iam/signals/sources).
func (api *SignalsAPI) ListSources(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsListSourcesInput]) (Out[apitypes.SignalsListSourcesOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:read", "signals/sources", func(ctx context.Context, call MutationContext) ([]any, error) {
		sources, err := call.Tx.Find(ctx, SignalCollections.Sources, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(sources, func(i, j int) bool {
			a, b := jsNumber(sources[i].Get("createdAt")), jsNumber(sources[j].Get("createdAt"))
			if a != b {
				return a < b
			}
			return compareUTF16(jsString(sources[i].Get("id")), jsString(sources[j].Get("id"))) < 0
		})
		views := make([]any, 0, len(sources))
		for _, source := range sources {
			views = append(views, publicSignalSource(server, source))
		}
		return views, nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsListSourcesOutput]{}, err
	}
	return Out[apitypes.SignalsListSourcesOutput]{Value: result}, nil
}

// Poll is POST {basePath}/signals/poll. Polls one poll source now (iam:signals:manage on iam/signals/sources/{id}),
// as the scheduled `iam.signals.poll()` does: the permission and the source are checked first, then the transmitter
// is called outside any transaction. INVALID_INPUT for a push source, INVALID_TRANSITION for a disabled one.
func (api *SignalsAPI) Poll(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsPollInput]) (Out[apitypes.SignalsPollOutput], error) {
	server := api.server
	sourceID, err := Text(input.Get("sourceId"), "sourceId")
	if err != nil {
		return Out[apitypes.SignalsPollOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	_, err = Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", signalSourceResource(sourceID), func(ctx context.Context, call MutationContext) (any, error) {
		source, err := api.scopedSource(ctx, call.Tx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		if source.Get("delivery") != "poll" {
			return nil, invalidInput("This source receives its events by push")
		}
		if source.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The source is disabled", 409)
		}
		return nil, nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsPollOutput]{}, err
	}
	result, err := SignalReceiverOf(server).Poll(ctx, core.NewObject("sourceId", sourceID))
	if err != nil {
		return Out[apitypes.SignalsPollOutput]{}, err
	}
	return Out[apitypes.SignalsPollOutput]{Value: result}, nil
}

// Reprocess is POST {basePath}/signals/reprocess. Maps and applies an `unmatched` or `failed` event again, after the
// source's mapping or the directory changed (iam:signals:manage on iam/signals/events/{id}, recent authentication;
// INVALID_TRANSITION for other statuses or a disabled source, NOT_FOUND when the source is gone). The configured action
// runs as on receipt; an event that now matches someone is audited as `signal:received` again for threat detection.
// Audited as `signal:reprocess`.
func (api *SignalsAPI) Reprocess(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsReprocessInput]) (Out[apitypes.SignalsReprocessOutput], error) {
	server := api.server
	eventID, err := Text(input.Get("eventId"), "eventId")
	if err != nil {
		return Out[apitypes.SignalsReprocessOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", signalEventResource(eventID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		record, err := server.Scoped(ctx, tx, SignalCollections.Events, eventID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		previousStatus := record.Get("status")
		if previousStatus != "unmatched" && previousStatus != "failed" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only unmatched and failed events can be reprocessed", 409)
		}
		source, err := tx.Get(ctx, SignalCollections.Sources, jsString(record.Get("sourceId")))
		if err != nil {
			return nil, err
		}
		if source == nil || !core.StrictEquals(source.Get("tenantId"), tenantID) {
			return nil, core.NewIamError("NOT_FOUND", "The source of this event no longer exists", 404)
		}
		if source.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The source of this event is disabled", 409)
		}
		var subject *core.SubjectIdentifier
		if truthy(record.Get("subject")) {
			subject = core.ParseSubjectIdentifier(record.Get("subject"))
		}
		claims, _ := record.Get("claims").(*core.Object)
		if claims == nil {
			claims = core.NewObject()
		}
		outcome, err := applySignal(ctx, server, tx, source, signalInput{
			eventType: jsString(record.Get("eventType")), subject: subject, event: claims, jti: jsString(record.Get("jti")),
		})
		if err != nil {
			return nil, err
		}
		next := record.Clone()
		next.Delete("identityId")
		next.Delete("reason")
		next.Set("status", outcome.status)
		if outcome.identityID != "" {
			next.Set("identityId", outcome.identityID)
		}
		if outcome.reason != "" {
			next.Set("reason", outcome.reason)
		}
		next.Set("reprocessedAt", float64(server.Now()))
		next.Set("reprocessedBy", principal.Identity.Get("id"))
		stored, err := tx.Put(ctx, SignalCollections.Events, next)
		if err != nil {
			return nil, err
		}
		if outcome.source != source {
			if _, err := tx.Put(ctx, SignalCollections.Sources, outcome.source); err != nil {
				return nil, err
			}
		}
		if truthy(stored.Get("identityId")) {
			if err := RecordSignalReceived(ctx, server, tx, source, stored, claims); err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject(
			"sourceId", source.Get("id"),
			"eventType", record.Get("eventType"),
			"jti", record.Get("jti"),
			"previousStatus", previousStatus,
			"status", stored.Get("status"),
		)
		if identityID := stored.Get("identityId"); truthy(identityID) {
			metadata.Set("identityId", identityID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "signal:reprocess", jsString(tenantID), signalEventResource(jsString(record.Get("id"))),
			"allow", false, metadata); err != nil {
			return nil, err
		}
		return publicSignalEvent(stored), nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsReprocessOutput]{}, err
	}
	return Out[apitypes.SignalsReprocessOutput]{Value: result}, nil
}

// RotatePushToken is POST {basePath}/signals/rotatePushToken. Replaces a push source's bearer token
// (iam:signals:manage on iam/signals/sources/{id}, recent authentication) and returns the new one, shown only here;
// the old one stops working at once. Also gives a push source created without a token one. Audited as
// `signal:source-rotate`.
func (api *SignalsAPI) RotatePushToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsRotatePushTokenInput]) (Out[apitypes.SignalsRotatePushTokenOutput], error) {
	server := api.server
	sourceID, err := Text(input.Get("sourceId"), "sourceId")
	if err != nil {
		return Out[apitypes.SignalsRotatePushTokenOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", signalSourceResource(sourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		source, err := api.scopedSource(ctx, tx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		if source.Get("delivery") != "push" {
			return nil, invalidInput("Only push sources have a push token")
		}
		pushToken := Token()
		if _, err := tx.Put(ctx, SignalCollections.Sources, source.Spread(core.NewObject(
			"pushTokenHash", Hash(pushToken),
			"updatedAt", float64(server.Now()),
			"updatedBy", principal.Identity.Get("id"),
		))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "signal:source-rotate", jsString(tenantID), signalSourceResource(jsString(source.Get("id"))),
			"allow", false, core.NewObject("replaced", !isUndefined(source.Get("pushTokenHash")))); err != nil {
			return nil, err
		}
		return core.NewObject("pushToken", pushToken), nil
	}, false)
	if err != nil {
		return Out[apitypes.SignalsRotatePushTokenOutput]{}, err
	}
	return Out[apitypes.SignalsRotatePushTokenOutput]{Value: result}, nil
}

// signalComparable is JSON.stringify(value ?? null).
func signalComparable(value any) string {
	if nullish(value) {
		return "null"
	}
	text, _, _ := core.Stringify(value)
	return text
}

// UpdateSource is POST {basePath}/signals/updateSource. Changes a source (iam:signals:manage on
// iam/signals/sources/{id}, recent authentication): names, aliases, audiences, keys (`null` clears `jwksUri` or
// `jwks`; without either, keys are discovered), algorithms, poll settings (a new endpoint needs its token again and
// starts with no pending acknowledgements), subject mapping, actions, `requireTyp` and `status` (a disabled source's
// pushes answer 404 and it is not polled). The issuer and delivery cannot change. Cached keys are dropped. An update
// that changes nothing is INVALID_INPUT. Audited as `signal:source-update` with the changed fields.
func (api *SignalsAPI) UpdateSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsUpdateSourceInput]) (Out[apitypes.SignalsUpdateSourceOutput], error) {
	fail := func(err error) (Out[apitypes.SignalsUpdateSourceOutput], error) {
		return Out[apitypes.SignalsUpdateSourceOutput]{}, err
	}
	server := api.server
	if !isUndefined(input.Get("issuer")) {
		return fail(invalidInput("The issuer of a source cannot change"))
	}
	if !isUndefined(input.Get("delivery")) {
		return fail(invalidInput("The delivery of a source cannot change"))
	}
	if !isUndefined(input.Get("pushToken")) {
		return fail(invalidInput("Use rotatePushToken to change the push token"))
	}
	sourceID, err := Text(input.Get("sourceId"), "sourceId")
	if err != nil {
		return fail(err)
	}
	changes := false
	for _, field := range signalUpdatableFields {
		changes = changes || !isUndefined(input.Get(field))
	}
	if !changes {
		return fail(invalidInput("The update changes nothing"))
	}
	status := input.Get("status")
	if !isUndefined(status) {
		if text, ok := status.(string); !ok || !signalSourceStatuses[text] {
			return fail(invalidInput("status must be active or disabled"))
		}
	}
	tenantID := input.Get("tenantId")
	updated, err := Operate(ctx, server.Operations, credential, tenantID, "iam:signals:manage", signalSourceResource(sourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		source, err := api.scopedSource(ctx, tx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		next := source.Spread()
		if value := input.Get("name"); !isUndefined(value) {
			name, err := Text(value, "name", 128)
			if err != nil {
				return nil, err
			}
			next.Set("name", core.JSTrim(name))
		}
		if value := input.Get("issuerAliases"); !isUndefined(value) {
			aliases, err := api.aliasesValue(value, jsString(source.Get("issuer")))
			if err != nil {
				return nil, err
			}
			next.Set("issuerAliases", aliases)
		}
		if value := input.Get("audiences"); !isUndefined(value) {
			audiences, err := WebIdentityAudiences(value)
			if err != nil {
				return nil, err
			}
			next.Set("audiences", stringsOf(audiences))
		}
		if value := input.Get("jwksUri"); value == nil {
			next.Delete("jwksUri")
		} else if !isUndefined(value) {
			jwksURI, err := api.urlValue(value, "jwksUri")
			if err != nil {
				return nil, err
			}
			next.Set("jwksUri", jwksURI)
		}
		if value := input.Get("jwks"); value == nil {
			next.Delete("jwks")
		} else if !isUndefined(value) {
			jwks, err := WebIdentityKeys(value)
			if err != nil {
				return nil, err
			}
			next.Set("jwks", jwks)
		}
		if !isUndefined(next.Get("jwksUri")) && !isUndefined(next.Get("jwks")) {
			return nil, invalidInput("Give jwks or jwksUri, not both")
		}
		if value := input.Get("algorithms"); !isUndefined(value) {
			algorithms, err := WebIdentityWebIdentityAlgorithms(value)
			if err != nil {
				return nil, err
			}
			next.Set("algorithms", stringsOf(algorithms))
		}
		if value := input.Get("poll"); !isUndefined(value) {
			current, _ := source.Get("poll").(*core.Object)
			if source.Get("delivery") != "poll" || current == nil {
				return nil, invalidInput("Only poll sources take poll settings")
			}
			poll, err := signalPollObject(value)
			if err != nil {
				return nil, err
			}
			state := current.Spread(core.NewObject("pendingAcks", core.CloneValue(current.Get("pendingAcks"))))
			if endpointValue := poll.Get("endpoint"); !isUndefined(endpointValue) {
				endpoint, err := api.urlValue(endpointValue, "poll.endpoint")
				if err != nil {
					return nil, err
				}
				if endpoint != current.Get("endpoint") {
					// The stored token was given for the old endpoint only; the new one's queue starts fresh.
					if isUndefined(poll.Get("token")) {
						return nil, invalidInput("A new poll endpoint needs its token again")
					}
					state.Set("endpoint", endpoint)
					state.Set("pendingAcks", []any{})
					state.Delete("pendingErrors")
				}
			}
			if tokenValue := poll.Get("token"); !isUndefined(tokenValue) {
				token, err := signalPollTokenValue(tokenValue)
				if err != nil {
					return nil, err
				}
				sealed, err := SealPollToken(server, jsString(source.Get("id")), token)
				if err != nil {
					return nil, err
				}
				state.Set("tokenSealed", sealed)
			}
			if maxValue := poll.Get("maxEvents"); !isUndefined(maxValue) {
				maxEvents, err := signalMaxEventsValue(maxValue)
				if err != nil {
					return nil, err
				}
				state.Set("maxEvents", maxEvents)
			}
			next.Set("poll", state)
		}
		if value := input.Get("subjects"); !isUndefined(value) {
			subjects, err := signalSubjectsValue(value, signalSubjects(source))
			if err != nil {
				return nil, err
			}
			next.Set("subjects", subjects)
		}
		if value := input.Get("actions"); !isUndefined(value) {
			actions, err := signalActionsValue(value)
			if err != nil {
				return nil, err
			}
			next.Set("actions", actions)
		}
		if value := input.Get("requireTyp"); !isUndefined(value) {
			requireTyp, err := signalBoolean(value, "requireTyp")
			if err != nil {
				return nil, err
			}
			next.Set("requireTyp", requireTyp)
		}
		if value := input.Get("tenantClaim"); value == nil {
			next.Delete("tenantClaim")
		} else if !isUndefined(value) {
			claim, err := Text(value, "tenantClaim")
			if err != nil {
				return nil, err
			}
			next.Set("tenantClaim", core.JSTrim(claim))
		}
		if !isUndefined(status) {
			next.Set("status", status)
		}
		changed := []string{}
		for _, field := range signalUpdatableFields {
			if signalComparable(source.Get(field)) != signalComparable(next.Get(field)) {
				changed = append(changed, field)
			}
		}
		if len(changed) == 0 {
			return nil, invalidInput("The update changes nothing")
		}
		next.Set("updatedAt", float64(server.Now()))
		next.Set("updatedBy", principal.Identity.Get("id"))
		stored, err := tx.Put(ctx, SignalCollections.Sources, next)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "signal:source-update", jsString(tenantID), signalSourceResource(jsString(source.Get("id"))),
			"allow", false, core.NewObject("changed", stringsOf(changed))); err != nil {
			return nil, err
		}
		return publicSignalSource(server, stored), nil
	}, false)
	if err != nil {
		return fail(err)
	}
	api.forget(jsString(updated.Get("id")))
	return Out[apitypes.SignalsUpdateSourceOutput]{Value: updated}, nil
}
