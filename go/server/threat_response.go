package server

// Port of packages/server/src/threat-response.ts: response actions of the threats module (threats.go): ending an
// identity's sessions, forgetting its remembered devices, containing it (disabled until `threats.release`),
// suspending its security clearance (until an officer's `clearances.reinstate`), blocking a network, and emailing an
// incident. The same primitives serve people responding through the API (who act under their own principal and are
// checked like the identities and security APIs check them) and automatic playbooks (the `threat-detection` actor,
// which never touches owners or root administrators and is braked by `maxAutomaticContainments`). Every action taken
// or skipped is kept as a `ThreatResponse` row for the incident timeline; the applied ones are audited under
// `threat:*` actions.
//
// Shapes (records and model values, as in TypeScript):
//   - ResponseActor: ThreatManualActor(principal) (`{ principal }`) or ThreatAutomaticActor() (`{ automatic: true }`).
//     The principal is stored with SetRaw, so it stays a *Principal.
//   - ResponseRequest: {action: {kind, durationMs?, keepApiKeys?}, subject: {type, id, name?}, identityId?, network?,
//     incidentId?, detectionId?, playbookId?, reason, actor}.
//   - PlaybookBrake: {contained, braked?}, updated in place.
//   - settings: ResolvedThreatSettings (ResolveThreatSettings).

import (
	"context"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// BlockDurationBounds is threat-response.ts blockDurationBounds: the bounds of a `block-network` response's length.
var BlockDurationBounds = struct {
	Min     float64
	Max     float64
	Default float64
}{threatsMinute, 30 * threatsDay, threatsDay}

// ThreatManualActor is the ResponseActor of a person responding through the API (`{ principal }`).
func ThreatManualActor(principal *Principal) *core.Object {
	return core.NewObject().SetRaw("principal", principal)
}

// ThreatAutomaticActor is the ResponseActor of the detection engine running a playbook (`{ automatic: true }`).
func ThreatAutomaticActor() *core.Object {
	return core.NewObject("automatic", true)
}

// threatManualPrincipal is the responding person of an actor, nil for the automatic actor.
func threatManualPrincipal(actor *core.Object) *Principal {
	if actor == nil || !actor.Has("principal") {
		return nil
	}
	principal, _ := actor.Get("principal").(*Principal)
	return principal
}

// threatActorID is the identity id of the responding person, or `threat-detection`.
func threatActorID(actor *core.Object) string {
	if principal := threatManualPrincipal(actor); principal != nil {
		return jsString(principal.Identity.Get("id"))
	}
	return ThreatActor
}

// ThreatAudit (threat-response.ts threatAudit): Records an audit event of the threats module: under the responding
// person (with their session context) or under the `threat-detection` actor, stamped with the service clock. Always
// `allow`, so SSF receivers and webhooks see it.
func ThreatAudit(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actor *core.Object, action string, resourceID string, metadata *core.Object) (err error) {
	if principal := threatManualPrincipal(actor); principal != nil {
		return server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
	}
	event := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"actorId", ThreatActor,
		"action", action,
		"resourceId", resourceID,
		"timestamp", float64(server.Now()),
		"outcome", "allow",
	)
	if metadata != nil {
		event.Set("metadata", metadata)
	}
	return server.Events.RecordAudit(ctx, tx, event)
}

// threatIdentityName is a display name for an identity: its name, else its email.
func threatIdentityName(identity *core.Object) string {
	for _, key := range []string{"name", "email", "id"} {
		if value := identity.Get(key); truthy(value) {
			return jsString(value)
		}
	}
	return jsString(identity.Get("id"))
}

// threatFirstAddress is a network's first address (the part before the slash).
func threatFirstAddress(network string) string {
	return strings.SplitN(network, "/", 2)[0]
}

// threatOverlaps: two networks (addresses or CIDR blocks) overlap when either contains the other's first address.
func threatOverlaps(a, b string) bool {
	return core.IPMatches(threatFirstAddress(a), b) || core.IPMatches(threatFirstAddress(b), a)
}

// threatPrefixOf is the prefix length of a network (an address counts as a full-length block).
func threatPrefixOf(network string) float64 {
	if slash := strings.Index(network, "/"); slash >= 0 {
		return stringToNumber(network[slash+1:])
	}
	if strings.Contains(network, ":") {
		return 128
	}
	return 32
}

// threatCovers is true when `outer` covers every address of `inner`.
func threatCovers(outer, inner string) bool {
	return threatPrefixOf(outer) <= threatPrefixOf(inner) && core.IPMatches(threatFirstAddress(inner), outer)
}

// threatReferences is the refs shared by the response row and the audit metadata.
func threatReferences(request *core.Object) *core.Object {
	refs := core.NewObject()
	for _, key := range []string{"incidentId", "detectionId", "playbookId"} {
		if value := request.Get(key); !isUndefined(value) {
			refs.Set(key, value)
		}
	}
	return refs
}

// threatIncidentRef is `{ incidentId }` when the request names one, else empty.
func threatIncidentRef(request *core.Object) *core.Object {
	out := core.NewObject()
	if value := request.Get("incidentId"); !isUndefined(value) {
		out.Set("incidentId", value)
	}
	return out
}

// ApplyResponse (threat-response.ts applyResponse): Takes one response action and records it: inserts the
// `ThreatResponse` row (applied or skipped with a reason) and, when applied, the audit event
// (`threat:revoke-sessions`, `threat:forget-devices`, `threat:contain`, `threat:suspend-clearance` after
// `clearance:suspend`, `threat:block-network`, `threat:notify`). Automatic actors skip protected targets (owners and
// root administrators are never contained, nor their clearances suspended, automatically) and, with a `brake`,
// containments beyond the tenant's `maxAutomaticContainments` (skipped `braked`, audited once per brake as
// `threat:response-braked`), and never block networks on the root tenant. People are refused instead: a root
// administrator only by root, an owner only by an owner in person or root, the last owner (`LAST_OWNER`),
// themselves, networks that cover their own address, blocks on the root tenant unless they are root, and a clearance
// suspension without `iam:clearances:suspend` (as `clearances.suspend` refuses it). Runs inside the caller's
// transaction; after it commits the caller runs `afterThreatResponses` (package reconciliation of contained
// identities, network block caches). `brake` is nil when there is none.
func ApplyResponse(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, request *core.Object, settings *core.Object, brake *core.Object) (result *core.Object, err error) {
	now := float64(server.Now())
	actor, _ := request.Get("actor").(*core.Object)
	principal := threatManualPrincipal(actor)
	actorID := threatActorID(actor)
	reason := orgSlice16(core.JSTrim(jsString(request.Get("reason"))), 512)
	if reason == "" {
		reason = "Threat response"
	}
	refs := threatReferences(request)
	action, _ := request.Get("action").(*core.Object)
	if action == nil {
		action = core.NewObject()
	}
	requestSubject, _ := request.Get("subject").(*core.Object)
	if requestSubject == nil {
		requestSubject = core.NewObject()
	}
	save := func(subject *core.Object, outcome string, why any, details *core.Object) (*core.Object, error) {
		row := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"action", action.Get("kind"),
			"subject", subject,
			"outcome", outcome,
		)
		if why != nil {
			row.Set("reason", why)
		}
		row.Assign(refs)
		row.Set("actorId", actorID)
		if details != nil {
			row.Set("details", details)
		}
		row.Set("createdAt", now)
		return tx.Insert(ctx, ThreatCollections.Responses, row)
	}
	skip := func(why string, subject *core.Object) (*core.Object, error) {
		if subject == nil {
			subject = requestSubject
		}
		return save(subject, "skipped", why, nil)
	}

	// target is the identity an identity action targets, or why there is none.
	target := func() (*core.Object, string, error) {
		var identityID any
		if requestSubject.Get("type") == "identity" {
			identityID = requestSubject.Get("id")
		} else {
			identityID = request.Get("identityId")
		}
		if !truthy(identityID) {
			return nil, "not-identity", nil
		}
		if principal != nil {
			identity, err := server.ActiveIdentity(ctx, tx, identityID, tenantID)
			return identity, "", err
		}
		identity, err := tx.Get(ctx, "identities", jsString(identityID))
		if err != nil {
			return nil, "", err
		}
		if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
			return nil, "not-found", nil
		}
		return identity, "", nil
	}
	identitySubject := func(identity *core.Object) *core.Object {
		return core.NewObject("type", "identity", "id", identity.Get("id"), "name", threatIdentityName(identity))
	}
	deleteAll := func(collection string, filter *core.Object) (float64, error) {
		rows, err := tx.Find(ctx, collection, filter, nil)
		if err != nil {
			return 0, err
		}
		removed := 0.0
		for _, row := range rows {
			if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
				return 0, err
			}
			removed++
		}
		return removed, nil
	}

	switch action.Get("kind") {
	case "revoke-sessions":
		identity, why, err := target()
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return skip(why, nil)
		}
		identityID := jsString(identity.Get("id"))
		// As identities.revokeSessions: a root administrator's sessions are ended by root (or by themselves).
		if principal != nil && truthy(identity.Get("rootAdmin")) && principal.Identity.Get("id") != identity.Get("id") {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, NewOperationDenied("Root capability is protected")
			}
		}
		keepAPIKeys := action.Get("keepApiKeys") != false
		// A person revoking their own sessions keeps the one they are responding from.
		var own any = core.Undefined
		if principal != nil {
			own = principal.Session.Get("id")
		}
		revoked := 0.0
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			if session.Get("id") == own || (keepAPIKeys && session.Get("kind") == "api-key") {
				continue
			}
			if err := server.Auth.EndSession(ctx, tx, jsString(session.Get("id"))); err != nil {
				return nil, err
			}
			revoked++
		}
		// Role sessions the identity assumed in other tenants, then delegated sessions acting as an agent.
		assumed, err := tx.Find(ctx, "sessions", core.NewObject("originalIdentityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, session := range assumed {
			if session.Get("id") == own || (keepAPIKeys && session.Get("kind") == "api-key") {
				continue
			}
			if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
				return nil, err
			}
			revoked++
		}
		if identity.Get("kind") == "agent" {
			deleted, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("agentId", identityID))
			if err != nil {
				return nil, err
			}
			revoked += deleted
		}
		if _, err := deleteAll("authChallenges", core.NewObject("identityId", identityID)); err != nil {
			return nil, err
		}
		metadata := core.NewObject("revoked", revoked, "keptApiKeys", keepAPIKeys, "reason", reason).Assign(refs)
		if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:revoke-sessions", identityID, metadata); err != nil {
			return nil, err
		}
		return save(identitySubject(identity), "applied", nil, core.NewObject("revoked", revoked, "keptApiKeys", keepAPIKeys))
	case "forget-devices":
		identity, why, err := target()
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return skip(why, nil)
		}
		identityID := jsString(identity.Get("id"))
		removed, err := deleteAll("authDevices", core.NewObject("identityId", identityID))
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("removed", removed, "reason", reason).Assign(refs)
		if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:forget-devices", identityID, metadata); err != nil {
			return nil, err
		}
		return save(identitySubject(identity), "applied", nil, core.NewObject("removed", removed))
	case "contain":
		return threatContain(ctx, server, tx, tenantID, request, settings, brake, actor, principal, actorID, reason, refs, now,
			target, identitySubject, deleteAll, save, skip)
	case "suspend-clearance":
		identity, why, err := target()
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return skip(why, nil)
		}
		identityID := jsString(identity.Get("id"))
		subject := identitySubject(identity)
		if principal != nil {
			// As clearances.suspend: the deployment enables clearances, and the responder may suspend this clearance
			// besides responding to threats (checked before anything about the clearance is read, so the response
			// tells nobody else whether the person holds one); never while impersonating, never a guest of the tenant.
			if err := AssertClearances(server); err != nil {
				return nil, err
			}
			if truthy(principal.Session.Get("impersonatorId")) {
				return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Clearances cannot be changed while impersonating", 403)
			}
			if !isUndefined(principal.Identity.Get("guest")) && principal.Identity.Get("tenantId") == tenantID {
				return nil, NewOperationDenied("Guests cannot suspend clearances")
			}
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID, Action: "iam:clearances:suspend", Resource: ResourceTarget{Type: "iam", ID: "clearances/" + identityID},
			}, true)
			if err != nil {
				return nil, err
			}
			if !decision.Allowed {
				return nil, NewOperationDenied("Suspending a clearance requires iam:clearances:suspend")
			}
		} else {
			if server.Config.Clearances == nil {
				return skip("feature-disabled", subject)
			}
			// As with containment, automatic responses never touch an owner's or a root administrator's clearance.
			if truthy(identity.Get("owner")) || truthy(identity.Get("rootAdmin")) {
				return skip("protected", subject)
			}
		}
		// Lifted only by an officer's clearances.reinstate; threats.release never touches it.
		input := core.NewObject("by", actorID, "at", now, "reason", reason).Assign(threatIncidentRef(request))
		suspended, err := SuspendClearance(ctx, tx, identity, input)
		if err != nil {
			return nil, err
		}
		if outcome := jsString(suspended.Get("outcome")); outcome != "suspended" {
			return skip(outcome, subject)
		}
		level := member(suspended.Get("record"), "level")
		// The clearance's own history (`clearance:*`, as clearances.suspend records it), then the response.
		history := core.NewObject("level", level, "reason", reason).Assign(threatIncidentRef(request))
		if err := ThreatAudit(ctx, server, tx, tenantID, actor, "clearance:suspend", identityID, history); err != nil {
			return nil, err
		}
		metadata := core.NewObject("level", level, "reason", reason).Assign(refs)
		if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:suspend-clearance", identityID, metadata); err != nil {
			return nil, err
		}
		return save(subject, "applied", nil, nil)
	case "block-network":
		return threatBlockNetwork(ctx, server, tx, tenantID, request, requestSubject, action, settings, actor, principal, actorID, reason, refs, now, save, skip)
	case "notify":
		var stored *core.Object
		if incidentID := request.Get("incidentId"); !isUndefined(incidentID) {
			if stored, err = tx.Get(ctx, ThreatCollections.Incidents, jsString(incidentID)); err != nil {
				return nil, err
			}
		}
		var incident *core.Object
		if stored != nil && stored.Get("tenantId") == tenantID {
			incident = stored
		}
		if incident == nil {
			return skip("no-incident", nil)
		}
		if !threatSendsEmail(server) {
			return skip("no-transport", nil)
		}
		recipients, err := threatIncidentRecipients(ctx, tx, tenantID, settings)
		if err != nil {
			return nil, err
		}
		if len(recipients) == 0 {
			return skip("no-recipients", nil)
		}
		if principal == nil {
			// Playbooks email an incident once, and again only when its severity has risen since.
			earlier, err := tx.Find(ctx, ThreatCollections.Responses, core.NewObject(
				"tenantId", tenantID, "incidentId", incident.Get("id"), "action", "notify", "outcome", "applied"), nil)
			if err != nil {
				return nil, err
			}
			for _, response := range earlier {
				severity, ok := member(response.Get("details"), "severity").(string)
				if ok && threatsRankAtLeast(threatsSeverityRank, severity, jsString(incident.Get("severity"))) {
					return skip("already-applied", nil)
				}
			}
		}
		sent, err := threatDeliverIncident(ctx, server, tx, tenantID, incident, recipients, actor)
		if err != nil {
			return nil, err
		}
		return save(requestSubject, "applied", nil, core.NewObject("recipients", sent, "severity", incident.Get("severity")))
	default:
		return nil, invalidInput("Unknown response action")
	}
}

// threatContain is the `contain` case of applyResponse.
func threatContain(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, request, settings, brake, actor *core.Object,
	principal *Principal, actorID, reason string, refs *core.Object, now float64,
	target func() (*core.Object, string, error), identitySubject func(*core.Object) *core.Object,
	deleteAll func(string, *core.Object) (float64, error),
	save func(*core.Object, string, any, *core.Object) (*core.Object, error),
	skip func(string, *core.Object) (*core.Object, error),
) (*core.Object, error) {
	identity, why, err := target()
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return skip(why, nil)
	}
	identityID := jsString(identity.Get("id"))
	subject := identitySubject(identity)
	if principal != nil && principal.Identity.Get("id") == identity.Get("id") {
		return nil, invalidInput("You cannot contain yourself")
	}
	stored, err := tx.Get(ctx, ThreatCollections.Risk, identityID)
	if err != nil {
		return nil, err
	}
	var risk *core.Object
	if stored != nil && stored.Get("tenantId") == tenantID {
		risk = stored
	}
	if identity.Get("status") != "active" {
		if risk != nil && truthy(risk.Get("contained")) {
			return skip("already-applied", subject)
		}
		return skip("inactive", subject)
	}
	if truthy(identity.Get("rootAdmin")) {
		if principal == nil {
			return skip("protected", subject)
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, NewOperationDenied("Root capability is protected")
		}
	}
	if truthy(identity.Get("owner")) && principal == nil {
		return skip("protected", subject)
	}
	if principal != nil {
		// As identities.setStatus: disabling an owner takes an owner of the tenant in person or a root principal,
		// never a permission alone.
		if err := AssertOwnerControl(ctx, server, tx, principal, identity, "Only an owner can contain an owner"); err != nil {
			return nil, err
		}
		if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
			return nil, err
		}
	}
	maxContainments := jsNumber(settings.Get("maxAutomaticContainments"))
	if brake != nil && jsNumber(brake.Get("contained")) >= maxContainments {
		first := !truthy(brake.Get("braked"))
		brake.Set("braked", jsNumber(coalesce(brake.Get("braked"), 0.0))+1)
		if first {
			resourceID := "threats/playbooks"
			if playbookID := request.Get("playbookId"); truthy(playbookID) {
				resourceID = "threats/playbooks/" + jsString(playbookID)
			}
			metadata := core.NewObject("threshold", settings.Get("maxAutomaticContainments"), "identityId", identityID).Assign(refs)
			if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:response-braked", resourceID, metadata); err != nil {
				return nil, err
			}
		}
		return skip("braked", subject)
	}
	if _, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", "disabled"))); err != nil {
		return nil, err
	}
	// Every credential but the API keys ends now; the keys are refused while the identity is disabled and work again
	// after a release, so containment is reversible without reissuing them.
	sessionsEnded := 0.0
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if session.Get("kind") == "api-key" {
			continue
		}
		if err := server.Auth.EndSession(ctx, tx, jsString(session.Get("id"))); err != nil {
			return nil, err
		}
		sessionsEnded++
	}
	assumed, err := tx.Find(ctx, "sessions", core.NewObject("originalIdentityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, session := range assumed {
		if session.Get("kind") == "api-key" {
			continue
		}
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return nil, err
		}
		sessionsEnded++
	}
	if identity.Get("kind") == "agent" {
		deleted, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("agentId", identityID))
		if err != nil {
			return nil, err
		}
		sessionsEnded += deleted
	}
	if _, err := deleteAll("authDevices", core.NewObject("identityId", identityID)); err != nil {
		return nil, err
	}
	if _, err := deleteAll("authChallenges", core.NewObject("identityId", identityID)); err != nil {
		return nil, err
	}
	// As when an identity is disabled: invitations it sent (an intruder's among them) stay dead after a release.
	if err := RevokeInvitationsBy(ctx, tx, identityID); err != nil {
		return nil, err
	}
	contained := core.NewObject("at", now, "by", actorID, "reason", reason).Assign(threatIncidentRef(request))
	if risk != nil {
		if _, err := tx.Put(ctx, ThreatCollections.Risk, risk.Spread(core.NewObject("contained", contained, "updatedAt", now))); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.Insert(ctx, ThreatCollections.Risk, core.NewObject(
			"id", identityID,
			"tenantId", tenantID,
			"identityId", identityID,
			"contributions", []any{},
			"score", 0.0,
			"level", "none",
			"contained", contained,
			"updatedAt", now,
		)); err != nil {
			return nil, err
		}
	}
	if brake != nil {
		brake.Set("contained", jsNumber(brake.Get("contained"))+1)
	}
	metadata := core.NewObject("reason", reason, "sessionsEnded", sessionsEnded).Assign(refs)
	if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:contain", identityID, metadata); err != nil {
		return nil, err
	}
	return save(subject, "applied", nil, core.NewObject("sessionsEnded", sessionsEnded))
}

// threatBlockNetwork is the `block-network` case of applyResponse.
func threatBlockNetwork(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, request, requestSubject, action, settings, actor *core.Object,
	principal *Principal, actorID, reason string, refs *core.Object, now float64,
	save func(*core.Object, string, any, *core.Object) (*core.Object, error),
	skip func(string, *core.Object) (*core.Object, error),
) (*core.Object, error) {
	var raw any
	if requestSubject.Get("type") == "network" {
		raw = requestSubject.Get("id")
	} else {
		raw = request.Get("network")
	}
	network := ""
	if text, ok := raw.(string); ok {
		network = core.JSTrim(text)
	}
	if network == "" {
		return skip("no-network", nil)
	}
	subject := core.NewObject("type", "network", "id", network)
	if !core.IsIPRange(network) {
		if principal != nil {
			return nil, invalidInput("network must be an IPv4/IPv6 address or CIDR block")
		}
		return skip("invalid-network", subject)
	}
	// As security.blockNetwork: the root tenant's blocks decide whether root administrators can sign in, so only
	// root sets them. Playbooks, which any iam:threats:manage holder may write, never do.
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant.Get("parentId") == nil {
		if principal == nil {
			return skip("protected", subject)
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, NewOperationDenied("Blocks on the root tenant are set by root administrators")
		}
	}
	trusted, _ := settings.Get("trustedNetworks").([]any)
	for _, entry := range trusted {
		if threatOverlaps(network, jsString(entry)) {
			return skip("trusted-network", subject)
		}
	}
	if principal != nil {
		// As security.blockNetwork: never the address the responder's session came from or this request comes from.
		own := []any{member(principal.Session.Get("client"), "ip")}
		if client := server.Auth.CurrentClient(ctx); client != nil && client.IP != "" {
			own = append(own, client.IP)
		}
		for _, ip := range own {
			if text, ok := ip.(string); ok && core.IPMatches(text, network) {
				return nil, invalidInput("That network includes your own address")
			}
		}
	}
	requested := coalesce(action.Get("durationMs"), BlockDurationBounds.Default)
	var durationMs float64
	if principal != nil {
		if durationMs, err = Integer(requested, "durationMs", BlockDurationBounds.Min, BlockDurationBounds.Max); err != nil {
			return nil, err
		}
	} else {
		chosen := BlockDurationBounds.Default
		if number, ok := requested.(float64); ok && core.IsSafeInteger(number) {
			chosen = number
		}
		durationMs = min(BlockDurationBounds.Max, max(BlockDurationBounds.Min, chosen))
	}
	expiresAt := now + durationMs
	// The tenant's own blocks plus the platform-wide ones, which apply to every tenant.
	own, err := tx.Find(ctx, "authBlocks", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	platform, err := tx.Find(ctx, "authBlocks", core.NewObject("platform", true), nil)
	if err != nil {
		return nil, err
	}
	blocks := append(append([]*core.Object{}, own...), platform...)
	// A block that already covers the network for at least as long makes this one redundant.
	lasting := func(block *core.Object) bool {
		value := block.Get("expiresAt")
		return isUndefined(value) || jsNumber(value) >= expiresAt
	}
	for _, block := range blocks {
		blockNetwork, _ := block.Get("network").(string)
		if core.IsIPRange(blockNetwork) && lasting(block) && threatCovers(blockNetwork, network) {
			return skip("already-applied", subject)
		}
	}
	var existing *core.Object
	for _, block := range blocks {
		if block.Get("tenantId") == tenantID && !truthy(block.Get("platform")) && block.Get("network") == network {
			existing = block
			break
		}
	}
	blockID := ID()
	if existing != nil {
		blockID = jsString(existing.Get("id"))
	}
	block := core.NewObject(
		"id", blockID,
		"tenantId", tenantID,
		"network", network,
		"reason", orgSlice16("threat: "+reason, 512),
		"createdAt", now,
		"createdBy", actorID,
		"expiresAt", expiresAt,
	)
	if existing != nil {
		_, err = tx.Put(ctx, "authBlocks", block)
	} else {
		_, err = tx.Insert(ctx, "authBlocks", block)
	}
	if err != nil {
		return nil, err
	}
	server.Auth.InvalidateNetworkBlocks()
	renewed := existing != nil
	metadata := core.NewObject("network", network, "expiresAt", expiresAt, "renewed", renewed, "reason", reason).Assign(refs)
	if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:block-network", "threats/networks/"+network, metadata); err != nil {
		return nil, err
	}
	return save(subject, "applied", nil, core.NewObject("network", network, "blockId", blockID, "expiresAt", expiresAt, "renewed", renewed))
}

// ReleaseIdentity (threat-response.ts releaseIdentity): Lifts a containment: the identity is active again and its
// risk record no longer marks it contained (the risk score is kept). Only an identity the threats module contained
// and that nothing else has disabled, suspended, or re-enabled since can be released (`INVALID_TRANSITION` 409
// otherwise, or when it has expired since); a root administrator only by root. Audited as `threat:release` and kept
// as a `release` response. After commit the caller runs `afterThreatResponses`. `note` is "" when absent.
func ReleaseIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string, actor *core.Object, note string) (result *core.Object, err error) {
	now := float64(server.Now())
	identity, err := server.ActiveIdentity(ctx, tx, identityID, tenantID)
	if err != nil {
		return nil, err
	}
	stored, err := tx.Get(ctx, ThreatCollections.Risk, jsString(identity.Get("id")))
	if err != nil {
		return nil, err
	}
	var risk *core.Object
	if stored != nil && stored.Get("tenantId") == tenantID {
		risk = stored
	}
	// A suspended agent is held by its kill switch (agents.resume lifts it); other paths that disable or re-enable an
	// identity drop the mark (endContainment), so what they did is never undone here.
	if risk == nil || !truthy(risk.Get("contained")) || identity.Get("status") != "disabled" ||
		truthy(member(identity.Get("agent"), "suspended")) {
		return nil, core.NewIamError("INVALID_TRANSITION", "The identity is not contained", 409)
	}
	principal := threatManualPrincipal(actor)
	if principal != nil && truthy(identity.Get("rootAdmin")) {
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, NewOperationDenied("Root capability is protected")
		}
	}
	if server.IdentityExpired(identity) {
		return nil, core.NewIamError("INVALID_TRANSITION", "Extend or clear expiresAt before releasing an expired identity", 409)
	}
	contained := risk.Get("contained")
	rest := risk.Spread()
	rest.Delete("contained")
	if _, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", "active"))); err != nil {
		return nil, err
	}
	if _, err := tx.Put(ctx, ThreatCollections.Risk, rest.Spread(core.NewObject("updatedAt", now))); err != nil {
		return nil, err
	}
	cleaned := orgSlice16(core.JSTrim(note), 1024)
	metadata := core.NewObject()
	if cleaned != "" {
		metadata.Set("note", cleaned)
	}
	metadata.Set("containedAt", member(contained, "at"))
	incidentID := member(contained, "incidentId")
	if !isUndefined(incidentID) {
		metadata.Set("incidentId", incidentID)
	}
	if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:release", jsString(identity.Get("id")), metadata); err != nil {
		return nil, err
	}
	row := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"action", "release",
		"subject", core.NewObject("type", "identity", "id", identity.Get("id"), "name", threatIdentityName(identity)),
		"outcome", "applied",
	)
	if !isUndefined(incidentID) {
		row.Set("incidentId", incidentID)
	}
	row.Set("actorId", threatActorID(actor))
	if cleaned != "" {
		row.Set("details", core.NewObject("note", cleaned))
	}
	row.Set("createdAt", now)
	return tx.Insert(ctx, ThreatCollections.Responses, row)
}

// threatSendsEmail is `ctx.options.authentication?.sendEmail` being set.
func threatSendsEmail(server *ServerContext) bool {
	return server.Options != nil && server.Options.Authentication != nil && server.Options.Authentication.SendEmail != nil
}

// threatIncidentRecipients is who is emailed about incidents: the tenant's listed addresses plus, when
// `notify.owners` is set, its active owners with a verified email. Lowercased, without duplicates, sorted.
func threatIncidentRecipients(ctx context.Context, tx core.IamStore, tenantID string, settings *core.Object) ([]string, error) {
	notify := settings.Get("notify")
	recipients := newOrderedSet()
	emails, _ := member(notify, "emails").([]any)
	for _, address := range emails {
		recipients.Add(core.JSLower(jsString(address)))
	}
	if truthy(member(notify, "owners")) {
		owners, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "owner", true, "status", "active"), nil)
		if err != nil {
			return nil, err
		}
		for _, owner := range owners {
			if truthy(owner.Get("email")) && truthy(owner.Get("emailVerified")) {
				recipients.Add(core.JSLower(jsString(owner.Get("email"))))
			}
		}
	}
	list := recipients.Values()
	// Array.prototype.sort: UTF-16 code unit order.
	sort.SliceStable(list, func(i, j int) bool { return compareUTF16(list[i], list[j]) < 0 })
	return list, nil
}

// threatDeliverIncident queues one `threat-alert` email per recipient and audits `threat:notify`; returns the number
// queued.
func threatDeliverIncident(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, incident *core.Object, recipients []string, actor *core.Object) (float64, error) {
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return 0, err
	}
	var latest *core.Object
	if detectionIDs, _ := incident.Get("detectionIds").([]any); len(detectionIDs) > 0 {
		if latestID := detectionIDs[len(detectionIDs)-1]; !isUndefined(latestID) {
			if latest, err = tx.Get(ctx, ThreatCollections.Detections, jsString(latestID)); err != nil {
				return 0, err
			}
		}
	}
	subject := incident.Get("subject")
	tenantName := any(tenantID)
	if tenant != nil {
		tenantName = coalesce(tenant.Get("name"), tenantID)
	}
	payload := core.NewObject(
		"incidentId", incident.Get("id"),
		"title", incident.Get("title"),
		"severity", incident.Get("severity"),
		"subject", coalesce(member(subject, "name"), member(subject, "id")),
		"subjectType", member(subject, "type"),
		"detections", jsString(incident.Get("detectionCount")),
		"tenantName", tenantName,
	)
	if latest != nil && latest.Get("tenantId") == tenantID {
		payload.Set("summary", latest.Get("summary"))
	}
	for _, to := range recipients {
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID, Kind: "email", To: to, Template: "threat-alert", Payload: payload,
		}); err != nil {
			return 0, err
		}
	}
	metadata := core.NewObject("recipients", float64(len(recipients)), "severity", incident.Get("severity"), "incidentId", incident.Get("id"))
	if err := ThreatAudit(ctx, server, tx, tenantID, actor, "threat:notify", "threats/incidents/"+jsString(incident.Get("id")), metadata); err != nil {
		return 0, err
	}
	return float64(len(recipients)), nil
}

// NotifyIncident (threat-response.ts notifyIncident): Emails an incident to the tenant's configured recipients
// (`threat-alert` template) and audits `threat:notify`. Sends nothing (`sent: 0`, no audit) without an email delivery
// callback or recipients. The automatic actor is used unless a responding person is given (actor nil: automatic).
// The result is {sent}.
func NotifyIncident(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, incident *core.Object, settings *core.Object, actor *core.Object) (*core.Object, error) {
	if actor == nil {
		actor = ThreatAutomaticActor()
	}
	if !threatSendsEmail(server) {
		return core.NewObject("sent", 0.0), nil
	}
	recipients, err := threatIncidentRecipients(ctx, tx, tenantID, settings)
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return core.NewObject("sent", 0.0), nil
	}
	sent, err := threatDeliverIncident(ctx, server, tx, tenantID, incident, recipients, actor)
	if err != nil {
		return nil, err
	}
	return core.NewObject("sent", sent), nil
}

// AfterThreatResponses (threat-response.ts afterThreatResponses): Post-commit follow-up of responses: reconciles
// access-package rules for identities contained or released (`afterIdentityChange`, which never throws) and clears
// this process's network block cache again after a block, so a read racing the transaction cannot keep the
// pre-change list for a few seconds.
func AfterThreatResponses(ctx context.Context, server *ServerContext, tenantID string, responses []*core.Object) (err error) {
	applied := []*core.Object{}
	for _, response := range responses {
		if response.Get("outcome") == "applied" {
			applied = append(applied, response)
		}
	}
	for _, response := range applied {
		if response.Get("action") == "block-network" {
			server.Auth.InvalidateNetworkBlocks()
			break
		}
	}
	changed := newOrderedSet()
	for _, response := range applied {
		action := response.Get("action")
		if (action == "contain" || action == "release") && member(response.Get("subject"), "type") == "identity" {
			changed.Add(jsString(member(response.Get("subject"), "id")))
		}
	}
	_, err = AfterIdentityChange(ctx, server, tenantID, changed.Values(), core.Undefined)
	return err
}
