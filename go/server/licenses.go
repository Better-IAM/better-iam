package server

// Port of packages/server/src/licenses.ts. License management: products (SKUs) defined by the platform (the root
// tenant, visible to every tenant) or by a tenant for its own subtree, capacity per consuming tenant as pools of seats,
// assignment to people and groups, and materialized seats. The claimants of a product in a tenant (direct assignees and
// live members of assigned groups, active and unexpired identities only) are ranked by seniority: the first `capacity`
// hold an active seat, the rest wait. What a license unlocks is expressed with existing governance: birthright package
// rules on `identity.licenses` (package-rules.ts, org-rules.ts), policies on `principal.licenses` (decisions.ts), and
// the feature keys a product lists (`iam.licenses.features`).

import (
	"context"
	"regexp"
	"sort"
	"sync"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// licenseContextKey is the policy key listing the product keys a person holds an active seat for in the decision's
// tenant.
const licenseContextKey = "principal.licenses"

var licenseKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// licenseSources is a seat's `sources` member (an object, or undefined).
func licenseSources(seat *core.Object) any { return seat.Get("sources") }

// licenseSeatDirect is `seat.sources.direct === true`.
func licenseSeatDirect(seat *core.Object) bool { return member(licenseSources(seat), "direct") == true }

// licenseSeatGroups is `seat.sources.groupIds ?? []` as strings.
func licenseSeatGroups(seat *core.Object) []string {
	list, _ := coalesce(member(licenseSources(seat), "groupIds"), []any{}).([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, jsString(item))
	}
	return out
}

// licenseString is a string member of a record (String() of anything else).
func licenseString(record *core.Object, key string) string { return jsString(record.Get(key)) }

// LicenseKey (licenses.ts licenseKey): Validates a product key: lowercase letters, digits, dots, underscores or
// hyphens, starting with a letter or digit.
func LicenseKey(value any) (result string, err error) {
	key, err := Text(value, "key", 64)
	if err != nil {
		return "", err
	}
	if !licenseKeyPattern.MatchString(key) {
		return "", invalidInput("License keys are 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	}
	return key, nil
}

// LiveLicensePool (licenses.ts liveLicensePool): Whether a pool contributes capacity at `now`.
func LiveLicensePool(pool *core.Object, now int64) (result bool, err error) {
	return liveLicensePool(pool, float64(now)), nil
}

func liveLicensePool(pool *core.Object, now float64) bool {
	startsAt, endsAt := pool.Get("startsAt"), pool.Get("endsAt")
	return (isUndefined(startsAt) || jsNumber(startsAt) <= now) && (isUndefined(endsAt) || jsNumber(endsAt) > now)
}

// LicenseCapacity (licenses.ts licenseCapacity): The seats a set of pools provides at `now`.
func LicenseCapacity(pools []*core.Object, now int64) (result float64, err error) {
	return licenseCapacity(pools, float64(now)), nil
}

func licenseCapacity(pools []*core.Object, now float64) float64 {
	sum := 0.0
	for _, pool := range pools {
		if liveLicensePool(pool, now) {
			sum += jsNumber(pool.Get("quantity"))
		}
	}
	return sum
}

// licenseChainIDs is chainIds: the tenant and its ancestors, nearest first, tolerant of missing records (readers
// without a server context).
func licenseChainIDs(ctx context.Context, reader core.IamStore, tenantID string) ([]string, error) {
	ids := []string{}
	current := tenantID
	for current != "" && len(ids) < 64 && !containsString(ids, current) {
		ids = append(ids, current)
		tenant, err := reader.Get(ctx, "tenants", current)
		if err != nil {
			return nil, err
		}
		current = ""
		if tenant != nil {
			if parent, ok := tenant.Get("parentId").(string); ok {
				current = parent
			}
		}
	}
	return ids, nil
}

// VisibleLicenseProducts (licenses.ts visibleLicenseProducts): Every product visible to a tenant: its own and those
// of its ancestors (the root tenant's are platform products).
func VisibleLicenseProducts(ctx context.Context, reader core.IamStore, tenantID string) (result []*core.Object, err error) {
	chain, err := licenseChainIDs(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	products := []*core.Object{}
	for _, definer := range chain {
		found, err := reader.Find(ctx, LicenseCollections.Products, core.NewObject("tenantId", definer), nil)
		if err != nil {
			return nil, err
		}
		products = append(products, found...)
	}
	return products, nil
}

// licenseGrantingOf is grantingOf: of the products visible to a tenant (nearest definer first), those whose seats
// grant their key there, by ID.
func licenseGrantingOf(visible []*core.Object) map[string]*core.Object {
	byKey := map[string]*core.Object{}
	// The last definition of a key is the one closest to the root: it wins.
	for _, product := range visible {
		byKey[licenseString(product, "key")] = product
	}
	granting := make(map[string]*core.Object, len(byKey))
	for _, product := range byKey {
		granting[licenseString(product, "id")] = product
	}
	return granting
}

// GrantingLicenseProducts (licenses.ts grantingLicenseProducts): The products whose seats grant their key in a
// tenant: those visible to it, except a product whose key a tenant enclosing its definer defines as well
// (`shadowed`). The definition closest to the root wins, so a tenant can never mint seats that count as a key the
// platform or an enclosing tenant sells, and a product of a tenant the seat's tenant is no longer below (after
// `tenants.reparent`) grants nothing there.
func GrantingLicenseProducts(ctx context.Context, reader core.IamStore, tenantID string) (result map[string]*core.Object, err error) {
	visible, err := VisibleLicenseProducts(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	return licenseGrantingOf(visible), nil
}

// LicenseRuleKeys (licenses.ts licenseRuleKeys): The valid `identity.licenses` values of a tenant: the keys of every
// product visible to it, retired ones included.
func LicenseRuleKeys(ctx context.Context, reader core.IamStore, tenantID string) (result []string, err error) {
	visible, err := VisibleLicenseProducts(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	keys := newOrderedSet()
	for _, product := range visible {
		keys.Add(licenseString(product, "key"))
	}
	return keys.Values(), nil
}

// TenantLicenseFacts is licenses.ts TenantLicenseFacts.
type TenantLicenseFacts struct {
	server *ServerContext
	// Keys The keys of every product visible to the tenant.
	Keys []string
	// products are the granting products by ID; seats the tenant's active seats by identity.
	products map[string]*core.Object
	seats    map[string][]*core.Object
}

// Of (licenses.ts TenantLicenseFacts.of): The keys of the products a person holds an active seat for. A seat held
// only through groups counts while one of them is in `countedGroupIds` (memberships no access package created), so a
// rule never feeds on what a package granted.
func (s *TenantLicenseFacts) Of(identityID string, countedGroupIDs []string) (result []string, err error) {
	counted := newOrderedSet(countedGroupIDs...)
	keys := newOrderedSet()
	for _, seat := range s.seats[identityID] {
		product := s.products[licenseString(seat, "productId")]
		if product == nil || product.Get("status") != "active" {
			continue
		}
		if !licenseSeatDirect(seat) {
			held := false
			for _, groupID := range licenseSeatGroups(seat) {
				if counted.Has(groupID) {
					held = true
					break
				}
			}
			if !held {
				continue
			}
		}
		keys.Add(licenseString(product, "key"))
	}
	values := keys.Values()
	sortStrings(values)
	if values == nil {
		values = []string{}
	}
	return values, nil
}

// LoadLicenseFacts (licenses.ts loadLicenseFacts): What `identity.licenses` holds for the people of one tenant, read
// once (org-rules.ts).
func LoadLicenseFacts(ctx context.Context, reader core.IamStore, tenantID string) (result *TenantLicenseFacts, err error) {
	visible, err := VisibleLicenseProducts(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	// Seats of a shadowed product (or of one the tenant no longer sees) never count.
	products := licenseGrantingOf(visible)
	seats := map[string][]*core.Object{}
	active, err := reader.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID, "status", "active"), nil)
	if err != nil {
		return nil, err
	}
	for _, seat := range active {
		identityID := licenseString(seat, "identityId")
		seats[identityID] = append(seats[identityID], seat)
	}
	keys := newOrderedSet()
	for _, product := range visible {
		keys.Add(licenseString(product, "key"))
	}
	values := keys.Values()
	if values == nil {
		values = []string{}
	}
	return &TenantLicenseFacts{Keys: values, products: products, seats: seats}, nil
}

// HeldLicenses (licenses.ts heldLicenses): The active seats of a person in a tenant that count right now: the
// product is active and grants its key in the tenant (`grantingLicenseProducts`: not shadowed by an enclosing
// tenant's product, still visible), and a seat held only through groups still has a live membership behind it
// (memberships lapse between reconciliations). Each entry is `{ product, seat }`.
func HeldLicenses(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result []*core.Object, err error) {
	found, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	var seats []*core.Object
	for _, seat := range found {
		if seat.Get("status") == "active" {
			seats = append(seats, seat)
		}
	}
	held := []*core.Object{}
	if len(seats) == 0 {
		return held, nil
	}
	var groups *orderedSet
	var granting map[string]*core.Object
	at := float64(now)
	for _, seat := range seats {
		if !licenseSeatDirect(seat) {
			if groups == nil {
				members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
				if err != nil {
					return nil, err
				}
				groups = newOrderedSet()
				for _, membership := range members {
					expiresAt := membership.Get("expiresAt")
					if isUndefined(expiresAt) || jsNumber(expiresAt) > at {
						groups.Add(licenseString(membership, "groupId"))
					}
				}
			}
			live := false
			for _, groupID := range licenseSeatGroups(seat) {
				if groups.Has(groupID) {
					live = true
					break
				}
			}
			if !live {
				continue
			}
		}
		if granting == nil {
			if granting, err = GrantingLicenseProducts(ctx, tx, tenantID); err != nil {
				return nil, err
			}
		}
		product := granting[licenseString(seat, "productId")]
		if product != nil && product.Get("status") == "active" {
			held = append(held, core.NewObject("product", product, "seat", seat))
		}
	}
	sort.SliceStable(held, func(i, j int) bool {
		return compareUTF16(heldKey(held[i]), heldKey(held[j])) < 0
	})
	return held, nil
}

// heldKey is the product key of a held license.
func heldKey(held *core.Object) string { return jsString(member(held.Get("product"), "key")) }

// MentionsLicenses (licenses.ts mentionsLicenses): whether any document names `principal.licenses` (conditions,
// `${…}` variables, resource patterns).
func MentionsLicenses(documents []any) bool {
	return anyStatementsMention(documents, licenseContextKey)
}

// LicenseContext (licenses.ts licenseContext): `principal.licenses` for a person in their own tenant: the keys of
// the products they hold an active seat for.
func LicenseContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result *core.Object, err error) {
	held, err := HeldLicenses(ctx, tx, tenantID, identityID, now)
	if err != nil {
		return nil, err
	}
	keys := newOrderedSet()
	for _, entry := range held {
		keys.Add(heldKey(entry))
	}
	values := keys.Values()
	sortStrings(values)
	return core.NewObject(licenseContextKey, stringsOf(values)), nil
}

// LastActivityOf (licenses.ts lastActivityOf): A person's latest activity: their last sign-in (`authSignIns`, else
// when the account was created) or the last use of one of their own sessions or API keys ("view as" sessions of
// administrators excluded).
func LastActivityOf(ctx context.Context, tx core.IamStore, identity *core.Object) (result float64, err error) {
	identityID := licenseString(identity, "id")
	ledger, err := tx.Get(ctx, "authSignIns", identityID)
	if err != nil {
		return 0, err
	}
	var last any = identity.Get("createdAt")
	if ledger != nil {
		last = coalesce(ledger.Get("lastAt"), identity.Get("createdAt"))
	}
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, session := range sessions {
		kind := session.Get("kind")
		if (kind == "user" || kind == "api-key") && !truthy(session.Get("impersonatorId")) &&
			jsNumber(session.Get("lastSeenAt")) > jsNumber(last) {
			last = session.Get("lastSeenAt")
		}
	}
	return jsNumber(last), nil
}

// licenseAuditAs is auditAs: a string actor is a system actor (recordAudit), anything else the acting principal.
func licenseAuditAs(ctx context.Context, server *ServerContext, tx core.IamStore, actor any, action, tenantID, resourceID string, metadata *core.Object) error {
	switch principal := actor.(type) {
	case *Principal:
		return server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
	case *auth.Principal:
		return server.Events.Audit(ctx, tx, PrincipalFromAuth(principal), action, tenantID, resourceID, "allow", false, metadata)
	}
	return server.Events.RecordAudit(ctx, tx, core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"actorId", actor,
		"action", action,
		"resourceId", resourceID,
		"timestamp", float64(server.Now()),
		"outcome", "allow",
		"metadata", metadata,
	))
}

// licenseSameGroups is sameGroups.
func licenseSameGroups(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// licenseChain is the seat tenant and its ancestors, read once per run.
type licenseChain struct {
	tenantID string
	ids      *orderedSet
}

// licenseProductRun is ProductRun.
type licenseProductRun struct {
	actor      any
	reason     string
	identities map[string]*core.Object
	chain      *licenseChain
}

func newLicenseRun(actor any, reason string) *licenseProductRun {
	return &licenseProductRun{actor: actor, reason: reason, identities: map[string]*core.Object{}}
}

// licenseClaim is why a person claims a seat of the product being reconciled.
type licenseClaim struct {
	direct   bool
	groupIDs *orderedSet
}

// licenseSeatChange is a LicenseSeatChange record.
func licenseSeatChange(tenantID, productID, productKey, identityID, from, to string) *core.Object {
	return core.NewObject("tenantId", tenantID, "productId", productID, "productKey", productKey,
		"identityId", identityID, "from", from, "to", to)
}

// licenseReconcileProduct is reconcileProduct: brings one product's seats in a tenant in line with its claimants and
// live capacity.
func licenseReconcileProduct(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID, productID string, run *licenseProductRun) ([]*core.Object, error) {
	now := float64(server.Now())
	product, err := tx.Get(ctx, LicenseCollections.Products, productID)
	if err != nil {
		return nil, err
	}
	seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID, "productId", productID), nil)
	if err != nil {
		return nil, err
	}
	claims := map[string]*licenseClaim{}
	var claimOrder []string
	claim := func(identityID string) *licenseClaim {
		entry := claims[identityID]
		if entry == nil {
			entry = &licenseClaim{groupIDs: newOrderedSet()}
			claims[identityID] = entry
			claimOrder = append(claimOrder, identityID)
		}
		return entry
	}
	capacity := 0.0
	if product != nil && (run.chain == nil || run.chain.tenantID != tenantID) {
		ids, err := licenseChainIDs(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		run.chain = &licenseChain{tenantID: tenantID, ids: newOrderedSet(ids...)}
	}
	// A retired (or vanished) product has no claimants: every seat goes. So does one the tenant no longer sees because
	// it moved out from under the defining tenant (`tenants.reparent`); its assignments stay and count again if it
	// returns.
	if product != nil && product.Get("status") == "active" && run.chain.ids.Has(licenseString(product, "tenantId")) {
		assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "productId", productID), nil)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			if assignment.Get("subjectType") == "identity" {
				claim(licenseString(assignment, "subjectId")).direct = true
				continue
			}
			members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "groupId", assignment.Get("subjectId")), nil)
			if err != nil {
				return nil, err
			}
			for _, membership := range members {
				if server.LiveMembership(membership) {
					claim(licenseString(membership, "identityId")).groupIDs.Add(licenseString(assignment, "subjectId"))
				}
			}
		}
		// Only active, unexpired identities of the tenant claim a seat (any kind; guests count like anyone).
		kept := claimOrder[:0:0]
		for _, identityID := range claimOrder {
			if _, known := run.identities[identityID]; !known {
				identity, err := tx.Get(ctx, "identities", identityID)
				if err != nil {
					return nil, err
				}
				run.identities[identityID] = identity
			}
			identity := run.identities[identityID]
			if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") != "active" || server.IdentityExpired(identity) {
				delete(claims, identityID)
				continue
			}
			kept = append(kept, identityID)
		}
		claimOrder = kept
		pools, err := tx.Find(ctx, LicenseCollections.Pools, core.NewObject("tenantId", tenantID, "productId", productID), nil)
		if err != nil {
			return nil, err
		}
		capacity = licenseCapacity(pools, now)
	}
	productKey := productID
	if product != nil {
		productKey = licenseString(product, "key")
	}
	existing := map[string]*core.Object{}
	for _, seat := range seats {
		existing[licenseString(seat, "identityId")] = seat
	}
	// Seniority decides: the oldest claims keep their seats, new claimants queue behind every existing seat. Claims of
	// the same millisecond rank existing seats before new ones and active before waiting, so a claimant never takes a
	// seat someone already holds and repeated runs never swap two holders.
	type rankedClaim struct {
		identityID string
		assignedAt float64
		rank       int
	}
	ranked := make([]rankedClaim, 0, len(claimOrder))
	for _, identityID := range claimOrder {
		entry := rankedClaim{identityID: identityID, assignedAt: now, rank: 2}
		if seat := existing[identityID]; seat != nil {
			entry.assignedAt = jsNumber(coalesce(seat.Get("assignedAt"), now))
			entry.rank = 1
			if seat.Get("status") == "active" {
				entry.rank = 0
			}
		}
		ranked = append(ranked, entry)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if difference := a.assignedAt - b.assignedAt; difference != 0 {
			return difference < 0
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return compareUTF16(a.identityID, b.identityID) < 0
	})
	changes := []*core.Object{}
	var settings *core.Object
	settingsRead := false
	var tenantName *string
	notify := func(identityID, template string) error {
		options := server.Options
		if product == nil || options == nil || options.Authentication == nil || options.Authentication.SendEmail == nil {
			return nil
		}
		if !settingsRead {
			found, err := tx.Get(ctx, LicenseCollections.Settings, tenantID)
			if err != nil {
				return err
			}
			settings, settingsRead = found, true
		}
		if settings == nil || settings.Get("notifyWaiting") != true {
			return nil
		}
		identity := run.identities[identityID]
		if identity == nil {
			found, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return err
			}
			identity = found
		}
		if identity == nil || !truthy(identity.Get("email")) || identity.Get("kind") != "user" || identity.Get("status") != "active" {
			return nil
		}
		if tenantName == nil {
			name := ""
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil {
				return err
			}
			if tenant != nil && !nullish(tenant.Get("name")) {
				name = licenseString(tenant, "name")
			}
			tenantName = &name
		}
		_, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID,
			Kind:     "email",
			To:       licenseString(identity, "email"),
			Template: template,
			Payload: core.NewObject(
				"tenantId", tenantID,
				"tenantName", *tenantName,
				"productKey", product.Get("key"),
				"productName", product.Get("name"),
			),
		})
		return err
	}
	record := func(identityID, from, to string) error {
		changes = append(changes, licenseSeatChange(tenantID, productID, productKey, identityID, from, to))
		action := "license:seat-waiting"
		if to == "none" {
			action = "license:seat-release"
		} else if to == "active" {
			action = "license:seat-activate"
		}
		if err := licenseAuditAs(ctx, server, tx, run.actor, action, tenantID, identityID, core.NewObject(
			"productId", productID, "productKey", productKey, "from", from, "to", to, "reason", run.reason,
		)); err != nil {
			return err
		}
		if to == "waiting" {
			return notify(identityID, "license-waiting")
		} else if from == "waiting" && to == "active" {
			return notify(identityID, "license-activated")
		}
		return nil
	}
	for _, seat := range seats {
		if _, claimed := claims[licenseString(seat, "identityId")]; !claimed {
			if err := tx.Delete(ctx, LicenseCollections.Seats, licenseString(seat, "id")); err != nil {
				return nil, err
			}
			if err := record(licenseString(seat, "identityId"), licenseString(seat, "status"), "none"); err != nil {
				return nil, err
			}
		}
	}
	for index, entry := range ranked {
		identityID, assignedAt := entry.identityID, entry.assignedAt
		status := "waiting"
		if float64(index) < capacity {
			status = "active"
		}
		source := claims[identityID]
		groupIDs := source.groupIDs.Values()
		sortStrings(groupIDs)
		sources := core.NewObject()
		if source.direct {
			sources.Set("direct", true)
		}
		if len(groupIDs) > 0 {
			sources.Set("groupIds", stringsOf(groupIDs))
		}
		seat := existing[identityID]
		if seat == nil {
			created := core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", productID+":"+identityID,
				"productId", productID,
				"identityId", identityID,
				"status", status,
				"sources", sources,
				"assignedAt", assignedAt,
			)
			if status == "active" {
				created.Set("activatedAt", now)
			}
			if _, err := tx.Insert(ctx, LicenseCollections.Seats, created); err != nil {
				return nil, err
			}
			if err := record(identityID, "none", status); err != nil {
				return nil, err
			}
			continue
		}
		sameSources := licenseSeatDirect(seat) == source.direct && licenseSameGroups(licenseSeatGroups(seat), groupIDs)
		if seat.Get("status") == status && sameSources {
			continue
		}
		previousActivation := seat.Get("activatedAt")
		next := seat.Spread()
		next.Delete("activatedAt")
		next.Delete("sources")
		next.Set("status", status)
		next.Set("sources", sources)
		if status == "active" {
			if seat.Get("status") == "active" {
				next.Set("activatedAt", coalesce(previousActivation, now))
			} else {
				next.Set("activatedAt", now)
			}
		}
		if _, err := tx.Put(ctx, LicenseCollections.Seats, next); err != nil {
			return nil, err
		}
		if seat.Get("status") != status {
			if err := record(identityID, licenseString(seat, "status"), status); err != nil {
				return nil, err
			}
		}
	}
	return changes, nil
}

// licensedProductIDs is licensedProductIds: the products with assignments or seats in a tenant.
func licensedProductIDs(ctx context.Context, tx core.IamStore, tenantID string) ([]string, error) {
	ids := newOrderedSet()
	assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		ids.Add(licenseString(assignment, "productId"))
	}
	seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, seat := range seats {
		ids.Add(licenseString(seat, "productId"))
	}
	values := ids.Values()
	sortStrings(values)
	return values, nil
}

// ReconcileLicenses (licenses.ts reconcileLicenses): Brings the seats of one product (or of every product with
// assignments or seats) in a tenant in line with who claims them and the capacity of the live pools. Idempotent.
// Seats of claimants who are gone (unassigned, left the group, disabled, expired, deleted) are released; the rest
// are ranked by seniority, the first `capacity` active and the others waiting, so capacity is never over-allocated
// and a capacity cut moves the newest active seats to the waiting list. Changes are audited as
// `license:seat-activate`, `license:seat-waiting` and `license:seat-release` (resource: the identity). Callers run
// `afterIdentityChange` post-commit for the identities in the result.
//
// An empty productID reconciles every product; options holds `actor` (a *Principal or a system actor string, set
// with SetRaw) and `reason`.
func ReconcileLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, productID string, options *core.Object) (result []*core.Object, err error) {
	var actor any = core.Undefined
	var reason any = core.Undefined
	if options != nil {
		actor, reason = options.Get("actor"), options.Get("reason")
	}
	var product *string
	if productID != "" {
		product = &productID
	}
	reasonText := "reconcile"
	if !nullish(reason) {
		reasonText = jsString(reason)
	}
	return reconcileLicenses(ctx, server, tx, tenantID, product, actor, reasonText)
}

// reconcileLicenses is reconcileLicenses with its options spelled out (actor undefined: `deployment-operator`).
func reconcileLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, productID *string, actor any, reason string) ([]*core.Object, error) {
	run := newLicenseRun(licenseActor(actor), reason)
	var productIDs []string
	if productID != nil {
		productIDs = []string{*productID}
	} else {
		var err error
		if productIDs, err = licensedProductIDs(ctx, tx, tenantID); err != nil {
			return nil, err
		}
	}
	changes := []*core.Object{}
	for _, each := range productIDs {
		found, err := licenseReconcileProduct(ctx, server, tx, tenantID, each, run)
		if err != nil {
			return nil, err
		}
		changes = append(changes, found...)
	}
	return changes, nil
}

// licenseActor is `actor ?? 'deployment-operator'`.
func licenseActor(actor any) any {
	if nullish(actor) {
		return "deployment-operator"
	}
	if principal, ok := actor.(*Principal); ok && principal == nil {
		return "deployment-operator"
	}
	return actor
}

// licenseDeferred is one product a batch of membership writes left to reconcile.
type licenseDeferred struct {
	tenantID  string
	productID string
	actor     any
}

// deferredGroupProducts is, per transaction, the products a batch of membership writes left to reconcile
// (`batchGroupLicenses`; a WeakMap keyed by the transaction in TypeScript).
var deferredGroupProducts sync.Map

// BatchGroupLicenses (licenses.ts batchGroupLicenses): Runs a batch of group membership writes (`groups.addMembers`,
// offboarding, configuration sync) with the seat reconciliation they cause deferred to the end of the batch, where
// each affected product is reconciled once instead of once per membership: every run rebuilds all of the product's
// claimants, which made batches quadratic inside the transaction. People who claim a seat in the same batch rank by
// identity ID among themselves. Nested batches join the outermost one.
func BatchGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, run func(context.Context) (any, error)) (result any, err error) {
	if _, nested := deferredGroupProducts.Load(tx); nested {
		return run(ctx)
	}
	pending := map[string]licenseDeferred{}
	deferredGroupProducts.Store(tx, pending)
	func() {
		defer deferredGroupProducts.Delete(tx)
		result, err = run(ctx)
	}()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		entry := pending[key]
		productID := entry.productID
		if _, err := reconcileLicenses(ctx, server, tx, entry.tenantID, &productID, entry.actor, "group-membership"); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// GroupsHoldLicenses (licenses.ts groupsHoldLicenses): Whether a product that still holds seats (an active one) is
// assigned to any of the groups.
func GroupsHoldLicenses(ctx context.Context, tx core.IamStore, tenantID string, groupIDs []string) (result bool, err error) {
	for _, groupID := range unique(groupIDs) {
		assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return false, err
		}
		for _, assignment := range assignments {
			product, err := tx.Get(ctx, LicenseCollections.Products, licenseString(assignment, "productId"))
			if err != nil {
				return false, err
			}
			if product != nil && product.Get("status") == "active" {
				return true, nil
			}
		}
	}
	return false, nil
}

// licenseGroupIDs reads `string | readonly string[]` group IDs.
func licenseGroupIDs(groupIDs any) []string {
	switch value := groupIDs.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			out = append(out, jsString(item))
		}
		return out
	}
	return nil
}

// ReconcileGroupLicenses (licenses.ts reconcileGroupLicenses): The products assigned to some groups, after their
// membership changed (teams.ts `syncTeamsFromGroups`): each product is reconciled once. Inside `batchGroupLicenses`
// the products are only noted, for the end of the batch.
func ReconcileGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, groupIDs any, actor any) (result []*core.Object, err error) {
	found := newOrderedSet()
	for _, groupID := range unique(licenseGroupIDs(groupIDs)) {
		assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			found.Add(licenseString(assignment, "productId"))
		}
	}
	productIDs := found.Values()
	sortStrings(productIDs)
	if pending, deferred := deferredGroupProducts.Load(tx); deferred {
		products := pending.(map[string]licenseDeferred)
		for _, productID := range productIDs {
			key := tenantID + ":" + productID
			if _, noted := products[key]; !noted {
				products[key] = licenseDeferred{tenantID: tenantID, productID: productID, actor: actor}
			}
		}
		return []*core.Object{}, nil
	}
	changes := []*core.Object{}
	for _, productID := range productIDs {
		each := productID
		found, err := reconcileLicenses(ctx, server, tx, tenantID, &each, actor, "group-membership")
		if err != nil {
			return nil, err
		}
		changes = append(changes, found...)
	}
	return changes, nil
}

// ReleaseGroupLicenses (licenses.ts releaseGroupLicenses): When a group is deleted: its license assignments go with
// it, and the seats they carried follow.
func ReleaseGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, groupID string, actor any) (result []*core.Object, err error) {
	productIDs := newOrderedSet()
	assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		productIDs.Add(licenseString(assignment, "productId"))
		if err := tx.Delete(ctx, LicenseCollections.Assignments, licenseString(assignment, "id")); err != nil {
			return nil, err
		}
	}
	ids := productIDs.Values()
	sortStrings(ids)
	changes := []*core.Object{}
	for _, productID := range ids {
		each := productID
		found, err := reconcileLicenses(ctx, server, tx, tenantID, &each, actor, "group-deleted")
		if err != nil {
			return nil, err
		}
		changes = append(changes, found...)
	}
	return changes, nil
}

// ReleaseLicensesOf (licenses.ts releaseLicensesOf): When a person is deleted: their direct assignments go and their
// seats are released (their group memberships are already gone), and waiting people move up.
func ReleaseLicensesOf(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, actor any) (result []*core.Object, err error) {
	tenantID := licenseString(identity, "tenantId")
	identityID := licenseString(identity, "id")
	productIDs := newOrderedSet()
	assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		productIDs.Add(licenseString(assignment, "productId"))
		if err := tx.Delete(ctx, LicenseCollections.Assignments, licenseString(assignment, "id")); err != nil {
			return nil, err
		}
	}
	seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, seat := range seats {
		productIDs.Add(licenseString(seat, "productId"))
	}
	changes := []*core.Object{}
	run := newLicenseRun(actor, "identity-deleted")
	// Whatever still ties the person to a product (a membership written after the cleanup) must not keep a seat.
	run.identities[identityID] = nil
	ids := productIDs.Values()
	sortStrings(ids)
	for _, productID := range ids {
		found, err := licenseReconcileProduct(ctx, server, tx, tenantID, productID, run)
		if err != nil {
			return nil, err
		}
		changes = append(changes, found...)
	}
	return changes, nil
}

// ReconcileIdentityLicenses (licenses.ts reconcileIdentityLicenses): Reconciles, inside the caller's transaction,
// the products that concern some identities of a tenant (their seats, direct assignments, and assignments of their
// groups), after their status or memberships changed (SCIM provisioning through
// `protocolHost.identityStatusChanged`, and `reconcileLicensesOf`). Returns the seat changes.
func ReconcileIdentityLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityIDs []string, actor any) (result []*core.Object, err error) {
	if len(identityIDs) == 0 {
		return []*core.Object{}, nil
	}
	// Tenants without licenses pay one indexed lookup.
	one := 1
	anyAssignment, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID), &core.FindOptions{Limit: &one})
	if err != nil {
		return nil, err
	}
	if len(anyAssignment) == 0 {
		anySeat, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID), &core.FindOptions{Limit: &one})
		if err != nil {
			return nil, err
		}
		if len(anySeat) == 0 {
			return []*core.Object{}, nil
		}
	}
	productIDs := newOrderedSet()
	groups := map[string][]string{}
	for _, identityID := range unique(identityIDs) {
		seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, seat := range seats {
			productIDs.Add(licenseString(seat, "productId"))
		}
		assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			productIDs.Add(licenseString(assignment, "productId"))
		}
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, membership := range members {
			groupID := licenseString(membership, "groupId")
			if _, read := groups[groupID]; !read {
				assigned, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
				if err != nil {
					return nil, err
				}
				products := make([]string, 0, len(assigned))
				for _, assignment := range assigned {
					products = append(products, licenseString(assignment, "productId"))
				}
				groups[groupID] = products
			}
			for _, productID := range groups[groupID] {
				productIDs.Add(productID)
			}
		}
	}
	run := newLicenseRun(licenseActor(actor), "identity-change")
	changes := []*core.Object{}
	ids := productIDs.Values()
	sortStrings(ids)
	for _, productID := range ids {
		found, err := licenseReconcileProduct(ctx, server, tx, tenantID, productID, run)
		if err != nil {
			return nil, err
		}
		changes = append(changes, found...)
	}
	return changes, nil
}

// ReconcileLicensesOf (licenses.ts reconcileLicensesOf): Reconciles the products that concern some identities of a
// tenant (`reconcileIdentityLicenses`) in one transaction, after an administrator changed them
// (package-automation.ts `afterIdentityChange`). Returns the identities whose seats changed; never throws (the
// scheduled reconcile catches up).
func ReconcileLicensesOf(ctx context.Context, server *ServerContext, tenantID string, identityIDs []string, actor any) (result []string, err error) {
	if len(identityIDs) == 0 {
		return []string{}, nil
	}
	changed, failure := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]string, error) {
		changes, err := ReconcileIdentityLicenses(ctx, server, tx, tenantID, identityIDs, actor)
		if err != nil {
			return nil, err
		}
		seen := newOrderedSet()
		for _, change := range changes {
			seen.Add(licenseString(change, "identityId"))
		}
		values := seen.Values()
		if values == nil {
			values = []string{}
		}
		return values, nil
	})
	if failure != nil {
		return []string{}, nil
	}
	return changed, nil
}

// ResolveLicenseSettings (licenses.ts resolveLicenseSettings): A tenant's settings with defaults (reclaim off, no
// waiting-list email).
func ResolveLicenseSettings(ctx context.Context, reader core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := reader.Get(ctx, LicenseCollections.Settings, tenantID)
	if err != nil {
		return nil, err
	}
	settings := core.NewObject()
	if stored != nil && !isUndefined(stored.Get("reclaimAfterDays")) {
		settings.Set("reclaimAfterDays", stored.Get("reclaimAfterDays"))
	}
	settings.Set("notifyWaiting", stored != nil && stored.Get("notifyWaiting") == true)
	if stored != nil {
		settings.Set("updatedAt", stored.Get("updatedAt"))
		settings.Set("updatedBy", stored.Get("updatedBy"))
	}
	return settings, nil
}

// LicenseCollections is licenses.ts licenseCollections.
var LicenseCollections = struct {
	Products    string
	Pools       string
	Assignments string
	Seats       string
	Settings    string
}{"licenseProducts", "licensePools", "licenseAssignments", "licenseSeats", "licenseSettings"}

// LicensePoolRetentionMs is licenses.ts licensePoolRetentionMs.
const LicensePoolRetentionMs = 34560000000

// LicenseReclaimDays is licenses.ts licenseReclaimDays.
var LicenseReclaimDays = struct {
	Min float64
	Max float64
}{7, 365}

// MaxLicenseAssignmentsPerProduct is licenses.ts maxLicenseAssignmentsPerProduct.
const MaxLicenseAssignmentsPerProduct = 10000

// MaxLicenseFeatureKeys is licenses.ts maxLicenseFeatureKeys.
const MaxLicenseFeatureKeys = 50

// MaxLicensePoolQuantity is licenses.ts maxLicensePoolQuantity.
const MaxLicensePoolQuantity = 1000000

// MaxLicensePoolsPerProduct is licenses.ts maxLicensePoolsPerProduct.
const MaxLicensePoolsPerProduct = 100

// MaxLicenseProductsPerTenant is licenses.ts maxLicenseProductsPerTenant.
const MaxLicenseProductsPerTenant = 200
