package server

// Port of packages/server/src/api/licenses.ts. License management: products (SKUs) the platform or a tenant defines,
// pools of seats per consuming tenant, assignment to people and groups, seats with a waiting list, and inactive-seat
// reclaim. What a license unlocks is expressed with birthright package rules on `identity.licenses`, policies on
// `principal.licenses`, and product feature keys (`iam.licenses.features`). Actions: iam:licenses:read,
// iam:licenses:manage (products, pools, settings) and iam:licenses:assign, on `iam/licenses/products[/{id}]`,
// `iam/licenses/pools[/{id}]`, `iam/licenses/assignments`, `iam/licenses/seats` and `iam/licenses/settings`.

import (
	"context"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// LicensesAPI is the `licenses` API group (packages/server/src/api/licenses.ts createLicensesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/licenses/{method} onto it.
type LicensesAPI struct {
	server *ServerContext
}

// CreateLicensesAPI builds the `licenses` API group.
func CreateLicensesAPI(server *ServerContext) *LicensesAPI {
	return &LicensesAPI{server: server}
}

const licenseDay = 86_400_000

var (
	licenseSeatStatuses    = newOrderedSet("active", "waiting")
	licenseProductStatuses = newOrderedSet("active", "retired")
	licenseSubjectTypes    = newOrderedSet("identity", "group")
)

func licenseProductResource(productID string) string { return "licenses/products/" + productID }

func licensePoolResource(poolID string) string { return "licenses/pools/" + poolID }

// licenseByText is byText.
func licenseByText(a, b string) int { return compareUTF16(a, b) }

// licenseSubjectType is subjectType.
func licenseSubjectType(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !licenseSubjectTypes.Has(text) {
		return "", invalidInput("subjectType must be 'identity' or 'group'")
	}
	return text, nil
}

// licenseFeatureKeysOf is featureKeysOf: distinct valid feature keys, sorted.
func licenseFeatureKeysOf(value any) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) > MaxLicenseFeatureKeys {
		return nil, invalidInput("featureKeys must list at most " + core.NumberString(MaxLicenseFeatureKeys) + " feature keys")
	}
	keys := make([]string, 0, len(list))
	for _, item := range list {
		key, err := FeatureKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	keys = unique(keys)
	sortStrings(keys)
	return stringsOf(keys), nil
}

// licenseOptionalText is optionalText: undefined stays undefined, anything else is a trimmed text.
func licenseOptionalText(value any, name string, max int) (any, error) {
	if isUndefined(value) {
		return core.Undefined, nil
	}
	text, err := Text(value, name, max)
	if err != nil {
		return nil, err
	}
	return core.JSTrim(text), nil
}

// licenseTimestamp is timestamp.
func licenseTimestamp(value any, name string) (float64, error) {
	return Integer(value, name, 0, 9007199254740991)
}

// licenseWritable is writable.
func licenseWritable(realm *core.Object) error {
	if realm.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated", 409)
	}
	return nil
}

// licenseProductViews is productViews: the views and whether each product's key is also defined further up (chain
// nearest-first).
func licenseProductViews(products []*core.Object, chain []*core.Object, viewer string) []*core.Object {
	depth := map[string]int{}
	for index, realm := range chain {
		depth[licenseString(realm, "id")] = index
	}
	depthOf := func(tenantID string) int {
		if value, ok := depth[tenantID]; ok {
			return value
		}
		return -1
	}
	rootID := ""
	hasRoot := len(chain) > 0
	if hasRoot {
		rootID = licenseString(chain[len(chain)-1], "id")
	}
	views := make([]*core.Object, len(products))
	for index, product := range products {
		own := depthOf(licenseString(product, "tenantId"))
		shadowed := false
		for _, other := range products {
			if other.Get("id") != product.Get("id") && other.Get("key") == product.Get("key") && depthOf(licenseString(other, "tenantId")) > own {
				shadowed = true
				break
			}
		}
		scope := "tenant"
		if hasRoot && product.Get("tenantId") == rootID {
			scope = "platform"
		}
		view := core.NewObject("id", product.Get("id"), "key", product.Get("key"), "name", product.Get("name"))
		if !isUndefined(product.Get("description")) {
			view.Set("description", product.Get("description"))
		}
		view.Set("featureKeys", product.Get("featureKeys"))
		view.Set("status", product.Get("status"))
		view.Set("scope", scope)
		view.Set("definedBy", product.Get("tenantId"))
		view.Set("definedHere", product.Get("tenantId") == viewer)
		view.Set("shadowed", shadowed)
		view.Set("createdAt", product.Get("createdAt"))
		view.Set("createdBy", product.Get("createdBy"))
		view.Set("updatedAt", product.Get("updatedAt"))
		view.Set("updatedBy", product.Get("updatedBy"))
		views[index] = view
	}
	return views
}

// nullable is `value ?? null`.
func nullable(value any) any { return coalesce(value, nil) }

// licenseProductMetadata is productMetadata.
func licenseProductMetadata(product *core.Object) *core.Object {
	return core.NewObject(
		"productId", product.Get("id"),
		"key", product.Get("key"),
		"name", product.Get("name"),
		"description", nullable(product.Get("description")),
		"featureKeys", product.Get("featureKeys"),
		"status", product.Get("status"),
	)
}

// licensePoolMetadata is poolMetadata.
func licensePoolMetadata(pool, product *core.Object) *core.Object {
	return core.NewObject(
		"poolId", pool.Get("id"),
		"productId", product.Get("id"),
		"productKey", product.Get("key"),
		"quantity", pool.Get("quantity"),
		"startsAt", nullable(pool.Get("startsAt")),
		"endsAt", nullable(pool.Get("endsAt")),
		"source", pool.Get("source"),
		"subscriptionId", nullable(pool.Get("subscriptionId")),
	)
}

// licensePoolView is poolView; product carries `key` and `name`.
func licensePoolView(pool *core.Object, productKey, productName any, tenantName any, now float64) *core.Object {
	view := core.NewObject(
		"id", pool.Get("id"),
		"tenantId", pool.Get("tenantId"),
		"tenantName", tenantName,
		"productId", pool.Get("productId"),
		"productKey", productKey,
		"productName", productName,
		"quantity", pool.Get("quantity"),
	)
	for _, key := range []string{"startsAt", "endsAt", "note"} {
		if !isUndefined(pool.Get(key)) {
			view.Set(key, pool.Get(key))
		}
	}
	view.Set("source", pool.Get("source"))
	if !isUndefined(pool.Get("subscriptionId")) {
		view.Set("subscriptionId", pool.Get("subscriptionId"))
	}
	view.Set("live", liveLicensePool(pool, now))
	view.Set("createdAt", pool.Get("createdAt"))
	view.Set("createdBy", pool.Get("createdBy"))
	for _, key := range []string{"updatedAt", "updatedBy"} {
		if !isUndefined(pool.Get(key)) {
			view.Set(key, pool.Get(key))
		}
	}
	return view
}

// licenseCache is cached: records read by ID once per call.
type licenseCache struct {
	tx         core.IamStore
	collection string
	values     map[string]*core.Object
}

func newLicenseCache(tx core.IamStore, collection string) *licenseCache {
	return &licenseCache{tx: tx, collection: collection, values: map[string]*core.Object{}}
}

func (c *licenseCache) get(ctx context.Context, key string) (*core.Object, error) {
	if value, ok := c.values[key]; ok {
		return value, nil
	}
	value, err := c.tx.Get(ctx, c.collection, key)
	if err != nil {
		return nil, err
	}
	c.values[key] = value
	return value, nil
}

// licenseNames is the key and name of a product, its ID for both when it no longer exists.
func licenseNames(product *core.Object, productID any) (key, name any) {
	if product == nil {
		return productID, productID
	}
	return product.Get("key"), product.Get("name")
}

// licenseAssignmentView is assignmentView.
func licenseAssignmentView(ctx context.Context, tx core.IamStore, assignment *core.Object, productKey, productName any) (*core.Object, error) {
	subjectName := assignment.Get("subjectId")
	subjectEmail := any(core.Undefined)
	if assignment.Get("subjectType") == "identity" {
		identity, err := tx.Get(ctx, "identities", licenseString(assignment, "subjectId"))
		if err != nil {
			return nil, err
		}
		if identity != nil {
			subjectName = identity.Get("name")
			subjectEmail = identity.Get("email")
		}
	} else {
		group, err := tx.Get(ctx, "groups", licenseString(assignment, "subjectId"))
		if err != nil {
			return nil, err
		}
		if group != nil {
			subjectName = group.Get("name")
		}
	}
	view := core.NewObject(
		"id", assignment.Get("id"),
		"tenantId", assignment.Get("tenantId"),
		"productId", assignment.Get("productId"),
		"productKey", productKey,
		"productName", productName,
		"subjectType", assignment.Get("subjectType"),
		"subjectId", assignment.Get("subjectId"),
		"subjectName", subjectName,
	)
	if !isUndefined(subjectEmail) {
		view.Set("subjectEmail", subjectEmail)
	}
	view.Set("assignedBy", assignment.Get("assignedBy"))
	view.Set("assignedAt", assignment.Get("assignedAt"))
	return view, nil
}

// licenseWaitingPositions is waitingPositions: waiting-list places per seat ID, per product, by seniority.
func licenseWaitingPositions(seats []*core.Object) map[string]int {
	queues := map[string][]*core.Object{}
	var order []string
	for _, seat := range seats {
		if seat.Get("status") == "waiting" {
			productID := licenseString(seat, "productId")
			if _, ok := queues[productID]; !ok {
				order = append(order, productID)
			}
			queues[productID] = append(queues[productID], seat)
		}
	}
	positions := map[string]int{}
	for _, productID := range order {
		queue := queues[productID]
		sort.SliceStable(queue, func(i, j int) bool {
			a, b := queue[i], queue[j]
			if difference := jsNumber(a.Get("assignedAt")) - jsNumber(b.Get("assignedAt")); difference != 0 {
				return difference < 0
			}
			return licenseByText(licenseString(a, "identityId"), licenseString(b, "identityId")) < 0
		})
		for index, seat := range queue {
			positions[licenseString(seat, "id")] = index + 1
		}
	}
	return positions
}

// licenseFollowSeats is followSeats: package rules on `identity.licenses` re-evaluate for the people whose seats
// changed (post-commit, per tenant). afterIdentityChange never throws (the schedules catch up), so its outcome is not
// the caller's.
func licenseFollowSeats(ctx context.Context, server *ServerContext, seats []any) {
	byTenant := map[string]*orderedSet{}
	var order []string
	for _, item := range seats {
		change, _ := item.(*core.Object)
		if change == nil {
			continue
		}
		tenantID := licenseString(change, "tenantId")
		if _, ok := byTenant[tenantID]; !ok {
			byTenant[tenantID] = newOrderedSet()
			order = append(order, tenantID)
		}
		byTenant[tenantID].Add(licenseString(change, "identityId"))
	}
	for _, tenantID := range order {
		_, _ = AfterIdentityChange(ctx, server, tenantID, byTenant[tenantID].Values(), nil)
	}
}

// followResult runs followSeats over a result's `seats` and returns the result.
func licenseFollowResult(ctx context.Context, server *ServerContext, result *core.Object) *core.Object {
	if result != nil {
		seats, _ := result.Get("seats").([]any)
		licenseFollowSeats(ctx, server, seats)
	}
	return result
}

// licenseChanges converts seat changes into a model list.
func licenseChanges(changes []*core.Object) []any {
	out := make([]any, len(changes))
	for index, change := range changes {
		out[index] = change
	}
	return out
}

// licenseFailure is failure.
func licenseFailure(tenantID string, err error) *core.Object {
	code := "ERROR"
	if known, ok := asIamError(err); ok {
		code = known.Code
	}
	return core.NewObject("tenantId", tenantID, "code", code, "message", errorMessage(err))
}

// licenseTenantsFor is tenantsFor.
func licenseTenantsFor(ctx context.Context, server *ServerContext, tenantID any) ([]*core.Object, error) {
	if !isUndefined(tenantID) {
		id, err := Text(tenantID, "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, server.Store, id)
		if err != nil {
			return nil, err
		}
		return []*core.Object{tenant}, nil
	}
	tenants, err := server.Store.Find(ctx, "tenants", core.NewObject("status", "active"), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(tenants, func(i, j int) bool {
		return licenseByText(licenseString(tenants[i], "id"), licenseString(tenants[j], "id")) < 0
	})
	return tenants, nil
}

// licenseHasAny is whether a tenant has any record in a collection (one indexed lookup).
func licenseHasAny(ctx context.Context, tx core.IamStore, collection, tenantID string) (bool, error) {
	one := 1
	found, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID), &core.FindOptions{Limit: &one})
	return len(found) > 0, err
}

// ReconcileAllLicenses (api/licenses.ts reconcileAllLicenses): the scheduler job behind `iam.licenses.reconcile`: one
// transaction per tenant with licenses.
func ReconcileAllLicenses(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	tenants, activated, waiting, released := 0, 0, 0, 0
	failedTenants := []any{}
	tenantID := any(core.Undefined)
	if input != nil {
		tenantID = input.Get("tenantId")
	}
	realms, err := licenseTenantsFor(ctx, server, tenantID)
	if err != nil {
		return nil, err
	}
	for _, tenant := range realms {
		if tenant.Get("status") != "active" {
			continue
		}
		id := licenseString(tenant, "id")
		var changes []*core.Object
		licensed := false
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			assigned, err := licenseHasAny(ctx, tx, LicenseCollections.Assignments, id)
			if err != nil {
				return err
			}
			if !assigned {
				seated, err := licenseHasAny(ctx, tx, LicenseCollections.Seats, id)
				if err != nil {
					return err
				}
				if !seated {
					return nil
				}
			}
			licensed = true
			changes, err = reconcileLicenses(ctx, server, tx, id, nil, core.Undefined, "schedule")
			return err
		})
		if err != nil {
			failedTenants = append(failedTenants, licenseFailure(id, err))
			continue
		}
		if !licensed {
			continue
		}
		tenants++
		for _, change := range changes {
			switch change.Get("to") {
			case "active":
				activated++
			case "waiting":
				waiting++
			default:
				released++
			}
		}
		licenseFollowSeats(ctx, server, licenseChanges(changes))
	}
	return core.NewObject("tenants", float64(tenants), "activated", float64(activated), "waiting", float64(waiting),
		"released", float64(released), "failedTenants", failedTenants), nil
}

// ReclaimLicenses (api/licenses.ts reclaimLicenses): the scheduler job behind `iam.licenses.reclaim`: one transaction
// per tenant with reclaim turned on.
func ReclaimLicenses(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	tenants := 0
	reclaimed := []any{}
	failedTenants := []any{}
	requested := any(core.Undefined)
	if input != nil {
		requested = input.Get("tenantId")
	}
	var tenantIDs []string
	if !isUndefined(requested) {
		id, err := Text(requested, "tenantId")
		if err != nil {
			return nil, err
		}
		tenantIDs = []string{id}
	} else {
		settings, err := server.Store.Find(ctx, LicenseCollections.Settings, nil, nil)
		if err != nil {
			return nil, err
		}
		for _, entry := range settings {
			if !isUndefined(entry.Get("reclaimAfterDays")) {
				tenantIDs = append(tenantIDs, licenseString(entry, "tenantId"))
			}
		}
		sortStrings(tenantIDs)
	}
	for _, tenantID := range tenantIDs {
		var found []any
		var seats []*core.Object
		ran := false
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			found, seats = nil, nil
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			settings, err := ResolveLicenseSettings(ctx, tx, licenseString(tenant, "id"))
			if err != nil {
				return err
			}
			days := settings.Get("reclaimAfterDays")
			if tenant.Get("status") != "active" || isUndefined(days) {
				return nil
			}
			ran = true
			realmID := licenseString(tenant, "id")
			now := float64(server.Now())
			cutoff := now - jsNumber(days)*licenseDay
			identities := newLicenseCache(tx, "identities")
			activity := map[string]float64{}
			lastActivity := func(person *core.Object) (float64, error) {
				personID := licenseString(person, "id")
				if value, ok := activity[personID]; ok {
					return value, nil
				}
				value, err := LastActivityOf(ctx, tx, person)
				if err != nil {
					return 0, err
				}
				activity[personID] = value
				return value, nil
			}
			// Seats remember what this pass saw, for the console and exports.
			held, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", realmID), nil)
			if err != nil {
				return err
			}
			for _, seat := range held {
				holder, err := identities.get(ctx, licenseString(seat, "identityId"))
				if err != nil {
					return err
				}
				if holder == nil {
					continue
				}
				last, err := lastActivity(holder)
				if err != nil {
					return err
				}
				if current, ok := seat.Get("lastActivityAt").(float64); !ok || current != last {
					if _, err := tx.Put(ctx, LicenseCollections.Seats, seat.Spread(core.NewObject("lastActivityAt", last))); err != nil {
						return err
					}
				}
			}
			products := newLicenseCache(tx, LicenseCollections.Products)
			// Only a product that holds seats here has a seat to reclaim: the assignments of a retired product stay as
			// read-only history, and so do those of a product the tenant no longer sees (it moved away from the definer).
			ancestry, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return err
			}
			chain := newOrderedSet()
			for _, link := range ancestry {
				chain.Add(licenseString(link, "id"))
			}
			productIDs := newOrderedSet()
			assignments, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", realmID, "subjectType", "identity"), nil)
			if err != nil {
				return err
			}
			for _, assignment := range assignments {
				// Someone assigned within the window has not had the chance to use it yet.
				if jsNumber(assignment.Get("assignedAt")) > cutoff {
					continue
				}
				owner, err := products.get(ctx, licenseString(assignment, "productId"))
				if err != nil {
					return err
				}
				if owner == nil || owner.Get("status") != "active" || !chain.Has(licenseString(owner, "tenantId")) {
					continue
				}
				person, err := identities.get(ctx, licenseString(assignment, "subjectId"))
				if err != nil {
					return err
				}
				last := 0.0
				if person != nil && person.Get("status") != "deleted" {
					if last, err = lastActivity(person); err != nil {
						return err
					}
				}
				if last > cutoff {
					continue
				}
				if err := tx.Delete(ctx, LicenseCollections.Assignments, licenseString(assignment, "id")); err != nil {
					return err
				}
				key := owner.Get("key")
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", realmID,
					"actorId", "deployment-operator",
					"action", "license:reclaim",
					"resourceId", assignment.Get("subjectId"),
					"timestamp", now,
					"outcome", "allow",
					"metadata", core.NewObject(
						"productId", assignment.Get("productId"),
						"productKey", key,
						"assignedAt", assignment.Get("assignedAt"),
						"lastActivityAt", last,
						"reclaimAfterDays", days,
					),
				)); err != nil {
					return err
				}
				productIDs.Add(licenseString(assignment, "productId"))
				found = append(found, core.NewObject(
					"tenantId", realmID,
					"productId", assignment.Get("productId"),
					"productKey", key,
					"identityId", assignment.Get("subjectId"),
					"lastActivityAt", last,
				))
			}
			ids := productIDs.Values()
			sortStrings(ids)
			for _, productID := range ids {
				each := productID
				changes, err := reconcileLicenses(ctx, server, tx, realmID, &each, core.Undefined, "reclaim")
				if err != nil {
					return err
				}
				seats = append(seats, changes...)
			}
			return nil
		})
		if err != nil {
			failedTenants = append(failedTenants, licenseFailure(tenantID, err))
			continue
		}
		if !ran {
			continue
		}
		tenants++
		reclaimed = append(reclaimed, found...)
		licenseFollowSeats(ctx, server, licenseChanges(seats))
	}
	return core.NewObject("tenants", float64(tenants), "reclaimed", reclaimed, "failedTenants", failedTenants), nil
}

// platformGuard: platform products (the root tenant's) are defined and changed by a root administrator only.
func (api *LicensesAPI) platformGuard(ctx context.Context, tx core.IamStore, realm *core.Object, principal *Principal) error {
	if realm.Has("parentId") && realm.Get("parentId") == nil {
		root, err := api.server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		if !root {
			return NewOperationDenied("Platform license products are managed by a root administrator")
		}
	}
	return nil
}

// visibleProduct is a product visible to the realm, with the realm's ancestry.
func (api *LicensesAPI) visibleProduct(ctx context.Context, tx core.IamStore, realm *core.Object, productID any) (*core.Object, []*core.Object, error) {
	chain, err := api.server.Ancestry(ctx, tx, realm)
	if err != nil {
		return nil, nil, err
	}
	id, err := Text(productID, "productId")
	if err != nil {
		return nil, nil, err
	}
	product, err := tx.Get(ctx, LicenseCollections.Products, id)
	if err != nil {
		return nil, nil, err
	}
	visible := false
	if product != nil {
		for _, link := range chain {
			if link.Get("id") == product.Get("tenantId") {
				visible = true
				break
			}
		}
	}
	if !visible {
		return nil, nil, core.NewIamError("NOT_FOUND", "License product not found", 404)
	}
	return product, chain, nil
}

// ownProduct is a product the realm itself defines.
func (api *LicensesAPI) ownProduct(ctx context.Context, tx core.IamStore, realm *core.Object, productID any) (*core.Object, []*core.Object, error) {
	product, chain, err := api.visibleProduct(ctx, tx, realm, productID)
	if err != nil {
		return nil, nil, err
	}
	if product.Get("tenantId") != realm.Get("id") {
		return nil, nil, invalidInput("An enclosing tenant defines this product; change it there")
	}
	return product, chain, nil
}

// viewOf is the product's view in the realm, shadowing included.
func (api *LicensesAPI) viewOf(ctx context.Context, tx core.IamStore, realm, product *core.Object, chain []*core.Object) (*core.Object, error) {
	visible, err := VisibleLicenseProducts(ctx, tx, licenseString(realm, "id"))
	if err != nil {
		return nil, err
	}
	related := []*core.Object{product}
	for _, other := range visible {
		if other.Get("key") == product.Get("key") && other.Get("id") != product.Get("id") {
			related = append(related, other)
		}
	}
	return licenseProductViews(related, chain, licenseString(realm, "id"))[0], nil
}

// poolAuthority: pool changes are authorized in the product's defining tenant: root for platform products (capacity
// bought from the platform), the defining tenant's managers for their own products. Read outside the transaction to
// pick the tenant; the operation re-reads and refuses when it changed.
func (api *LicensesAPI) poolAuthority(ctx context.Context, productID *string, fallback any) (tenantID any, platform bool, err error) {
	var product *core.Object
	if productID != nil {
		if product, err = api.server.Store.Get(ctx, LicenseCollections.Products, *productID); err != nil {
			return nil, false, err
		}
	}
	var definer *core.Object
	if product != nil {
		if definer, err = api.server.Store.Get(ctx, "tenants", licenseString(product, "tenantId")); err != nil {
			return nil, false, err
		}
	}
	if definer != nil {
		return definer.Get("id"), definer.Has("parentId") && definer.Get("parentId") == nil, nil
	}
	return fallback, false, nil
}

// poolTarget is the consuming tenant and product of a pool change, checked against the authorizing (defining) tenant.
// With `detached`, a pool of a tenant that has since moved out from under the definer passes too, so the definer can
// still remove capacity it granted (`removePool`); nothing else changes such a pool.
func (api *LicensesAPI) poolTarget(ctx context.Context, tx core.IamStore, definer *core.Object, consumerID any, productID string, detached bool) (*core.Object, *core.Object, error) {
	server := api.server
	id, err := Text(consumerID, "tenantId")
	if err != nil {
		return nil, nil, err
	}
	consumer, err := server.Tenant(ctx, tx, id)
	if err != nil {
		return nil, nil, err
	}
	product, err := tx.Get(ctx, LicenseCollections.Products, productID)
	if err != nil {
		return nil, nil, err
	}
	if product == nil {
		return nil, nil, core.NewIamError("NOT_FOUND", "License product not found", 404)
	}
	if product.Get("tenantId") != definer.Get("id") {
		return nil, nil, core.NewIamError("CONFLICT", "The product changed; try again", 409)
	}
	if !detached {
		chain, err := server.Ancestry(ctx, tx, consumer)
		if err != nil {
			return nil, nil, err
		}
		below := false
		for _, link := range chain {
			if link.Get("id") == definer.Get("id") {
				below = true
				break
			}
		}
		if !below {
			return nil, nil, invalidInput("tenantId must be the tenant that defines the product or a tenant below it")
		}
	}
	if err := licenseWritable(consumer); err != nil {
		return nil, nil, err
	}
	if product.Get("status") != "active" {
		return nil, nil, core.NewIamError("INVALID_TRANSITION", "The product is retired; its pools are read-only", 409)
	}
	return product, consumer, nil
}

// consumerInvariants: capacity granted from an enclosing tenant moves seats in the receiving tenant, whose enforced
// access invariants the operation envelope (run in the defining tenant) does not check: they are checked around the
// change the same way. Call before changing anything; the returned function refuses (rolling back) a change that
// newly breaks one.
func (api *LicensesAPI) consumerInvariants(ctx context.Context, tx core.IamStore, definer, consumer *core.Object) (func() error, error) {
	var snapshot *InvariantSnapshotState
	consumerID := licenseString(consumer, "id")
	if consumer.Get("id") != definer.Get("id") {
		var err error
		if snapshot, err = InvariantSnapshot(ctx, api.server, tx, consumerID, "iam:licenses:manage"); err != nil {
			return nil, err
		}
	}
	return func() error { return InvariantVerify(ctx, api.server, tx, consumerID, snapshot) }, nil
}

// audit is an allow audit event of the acting principal.
func (api *LicensesAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
}

// licensePage is `rows.slice(offset, offset + limit)`.
func licensePage(rows []*core.Object, offset, limit float64) []*core.Object {
	start := int(math.Min(offset, float64(len(rows))))
	end := int(math.Min(offset+limit, float64(len(rows))))
	if end < start {
		end = start
	}
	return rows[start:end]
}

// licensePaging validates `limit` (default 100) and `offset` (default 0).
func licensePaging(input interface{ Get(string) any }) (limit, offset float64, err error) {
	if limit, err = Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000); err != nil {
		return 0, 0, err
	}
	if offset, err = Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000); err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// AddPool is POST {basePath}/licenses/addPool. Gives a tenant seats of a product: a quantity, optionally from a start until an end.
func (api *LicensesAPI) AddPool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAddPoolInput]) (Out[apitypes.LicensesAddPoolOutput], error) {
	server := api.server
	productID, err := Text(input.Get("productId"), "productId")
	if err != nil {
		return Out[apitypes.LicensesAddPoolOutput]{}, err
	}
	authority, platform, err := api.poolAuthority(ctx, &productID, input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.LicensesAddPoolOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, authority, "iam:licenses:manage", "licenses/pools", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, definer, principal := call.Tx, call.Tenant, call.Principal
		product, consumer, err := api.poolTarget(ctx, tx, definer, input.Get("tenantId"), productID, false)
		if err != nil {
			return nil, err
		}
		quantity, err := Integer(input.Get("quantity"), "quantity", 1, MaxLicensePoolQuantity)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		startsAt := any(core.Undefined)
		if !isUndefined(input.Get("startsAt")) {
			if startsAt, err = licenseTimestamp(input.Get("startsAt"), "startsAt"); err != nil {
				return nil, err
			}
		}
		endsAt := any(core.Undefined)
		if !isUndefined(input.Get("endsAt")) {
			if endsAt, err = licenseTimestamp(input.Get("endsAt"), "endsAt"); err != nil {
				return nil, err
			}
		}
		if !isUndefined(endsAt) && (jsNumber(endsAt) <= now || (!isUndefined(startsAt) && jsNumber(endsAt) <= jsNumber(startsAt))) {
			return nil, invalidInput("endsAt must be in the future and after startsAt")
		}
		note, err := licenseOptionalText(input.Get("note"), "note", 512)
		if err != nil {
			return nil, err
		}
		subscriptionID := any(core.Undefined)
		if !isUndefined(input.Get("subscriptionId")) {
			id, err := Text(input.Get("subscriptionId"), "subscriptionId")
			if err != nil {
				return nil, err
			}
			subscriptionID = id
			subscription, err := tx.Get(ctx, BillingCollections.Subscriptions, id)
			if err != nil {
				return nil, err
			}
			// The subscription belongs to the receiving tenant's billing account: itself or an enclosing tenant.
			owned := false
			if subscription != nil {
				chain, err := server.Ancestry(ctx, tx, consumer)
				if err != nil {
					return nil, err
				}
				for _, link := range chain {
					if link.Get("id") == subscription.Get("tenantId") {
						owned = true
						break
					}
				}
			}
			if !owned {
				return nil, core.NewIamError("NOT_FOUND", "Subscription not found", 404)
			}
		}
		consumerID := licenseString(consumer, "id")
		existing, err := tx.Find(ctx, LicenseCollections.Pools, core.NewObject("tenantId", consumerID, "productId", product.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) >= MaxLicensePoolsPerProduct {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can hold at most "+core.NumberString(MaxLicensePoolsPerProduct)+" pools of one product", 409)
		}
		verifyConsumer, err := api.consumerInvariants(ctx, tx, definer, consumer)
		if err != nil {
			return nil, err
		}
		record := core.NewObject("id", ID(), "tenantId", consumerID, "productId", product.Get("id"), "quantity", quantity)
		if !isUndefined(startsAt) {
			record.Set("startsAt", startsAt)
		}
		if !isUndefined(endsAt) {
			record.Set("endsAt", endsAt)
			record.Set("expiresAt", jsNumber(endsAt)+LicensePoolRetentionMs)
		}
		if !isUndefined(note) {
			record.Set("note", note)
		}
		if !isUndefined(subscriptionID) {
			record.Set("source", "subscription")
			record.Set("subscriptionId", subscriptionID)
		} else {
			record.Set("source", "manual")
		}
		record.Set("createdAt", now)
		record.Set("createdBy", principal.Identity.Get("id"))
		pool, err := tx.Insert(ctx, LicenseCollections.Pools, record)
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "license:pool-add", consumerID, licensePoolResource(licenseString(pool, "id")), licensePoolMetadata(pool, product)); err != nil {
			return nil, err
		}
		poolProductID := licenseString(product, "id")
		seats, err := reconcileLicenses(ctx, server, tx, consumerID, &poolProductID, principal, "pool-add")
		if err != nil {
			return nil, err
		}
		if err := verifyConsumer(); err != nil {
			return nil, err
		}
		return core.NewObject(
			"pool", licensePoolView(pool, product.Get("key"), product.Get("name"), consumer.Get("name"), now),
			"seats", licenseChanges(seats),
		), nil
	}, platform)
	if err != nil {
		return Out[apitypes.LicensesAddPoolOutput]{}, err
	}
	return Out[apitypes.LicensesAddPoolOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// Assign is POST {basePath}/licenses/assign. Gives a product to a person or a group of the tenant; the person, or each live member of the group, claims a seat.
func (api *LicensesAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAssignInput]) (Out[apitypes.LicensesAssignOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:assign", "licenses/assignments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := licenseWritable(realm); err != nil {
			return nil, err
		}
		product, _, err := api.visibleProduct(ctx, tx, realm, input.Get("productId"))
		if err != nil {
			return nil, err
		}
		if product.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The product is retired", 409)
		}
		kind, err := licenseSubjectType(input.Get("subjectType"))
		if err != nil {
			return nil, err
		}
		subjectID, err := Text(input.Get("subjectId"), "subjectId")
		if err != nil {
			return nil, err
		}
		if kind == "identity" {
			if _, err := server.ActiveIdentity(ctx, tx, subjectID, realmID); err != nil {
				return nil, err
			}
		} else if _, err := server.Scoped(ctx, tx, "groups", subjectID, realmID); err != nil {
			return nil, err
		}
		productID := licenseString(product, "id")
		uniqueKey := productID + ":" + kind + ":" + subjectID
		taken, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", realmID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		if len(taken) > 0 {
			return nil, core.NewIamError("CONFLICT", "The product is already assigned to this subject", 409)
		}
		existing, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", realmID, "productId", productID), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) >= MaxLicenseAssignmentsPerProduct {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+core.NumberString(MaxLicenseAssignmentsPerProduct)+" assignments per product; assign groups instead", 409)
		}
		assignment, err := tx.Insert(ctx, LicenseCollections.Assignments, core.NewObject(
			"id", ID(),
			"tenantId", realmID,
			"uniqueKey", uniqueKey,
			"productId", productID,
			"subjectType", kind,
			"subjectId", subjectID,
			"assignedBy", principal.Identity.Get("id"),
			"assignedAt", float64(server.Now()),
		))
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "license:assign", realmID, subjectID, core.NewObject(
			"assignmentId", assignment.Get("id"),
			"productId", productID,
			"productKey", product.Get("key"),
			"subjectType", kind,
		)); err != nil {
			return nil, err
		}
		seats, err := reconcileLicenses(ctx, server, tx, realmID, &productID, principal, "assign")
		if err != nil {
			return nil, err
		}
		view, err := licenseAssignmentView(ctx, tx, assignment, product.Get("key"), product.Get("name"))
		if err != nil {
			return nil, err
		}
		return core.NewObject("assignment", view, "seats", licenseChanges(seats)), nil
	}, false)
	if err != nil {
		return Out[apitypes.LicensesAssignOutput]{}, err
	}
	return Out[apitypes.LicensesAssignOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// AssignMany is POST {basePath}/licenses/assignMany. Gives a product to up to 100 people in one transaction.
func (api *LicensesAPI) AssignMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAssignManyInput]) (Out[apitypes.LicensesAssignManyOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:assign", "licenses/assignments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := licenseWritable(realm); err != nil {
			return nil, err
		}
		listed, err := Strings(input.Get("identityIds"), "identityIds")
		if err != nil {
			return nil, err
		}
		identityIDs := unique(listed)
		if len(identityIDs) == 0 {
			return nil, invalidInput("Provide 1-100 identityIds")
		}
		product, _, err := api.visibleProduct(ctx, tx, realm, input.Get("productId"))
		if err != nil {
			return nil, err
		}
		if product.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The product is retired", 409)
		}
		productID := licenseString(product, "id")
		existing, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", realmID, "productId", productID), nil)
		if err != nil {
			return nil, err
		}
		held := newOrderedSet()
		for _, assignment := range existing {
			held.Add(licenseString(assignment, "uniqueKey"))
		}
		assigned := []any{}
		skipped := []any{}
		for _, identityID := range identityIDs {
			if _, err := server.ActiveIdentity(ctx, tx, identityID, realmID); err != nil {
				return nil, err
			}
			uniqueKey := productID + ":identity:" + identityID
			if held.Has(uniqueKey) {
				skipped = append(skipped, identityID)
				continue
			}
			if len(existing)+len(assigned) >= MaxLicenseAssignmentsPerProduct {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "At most "+core.NumberString(MaxLicenseAssignmentsPerProduct)+" assignments per product; assign groups instead", 409)
			}
			assignment, err := tx.Insert(ctx, LicenseCollections.Assignments, core.NewObject(
				"id", ID(),
				"tenantId", realmID,
				"uniqueKey", uniqueKey,
				"productId", productID,
				"subjectType", "identity",
				"subjectId", identityID,
				"assignedBy", principal.Identity.Get("id"),
				"assignedAt", float64(server.Now()),
			))
			if err != nil {
				return nil, err
			}
			held.Add(uniqueKey)
			if err := api.audit(ctx, tx, principal, "license:assign", realmID, identityID, core.NewObject(
				"assignmentId", assignment.Get("id"),
				"productId", productID,
				"productKey", product.Get("key"),
				"subjectType", "identity",
			)); err != nil {
				return nil, err
			}
			view, err := licenseAssignmentView(ctx, tx, assignment, product.Get("key"), product.Get("name"))
			if err != nil {
				return nil, err
			}
			assigned = append(assigned, view)
		}
		seats := []*core.Object{}
		if len(assigned) > 0 {
			if seats, err = reconcileLicenses(ctx, server, tx, realmID, &productID, principal, "assign"); err != nil {
				return nil, err
			}
		}
		return core.NewObject("assigned", assigned, "skipped", skipped, "seats", licenseChanges(seats)), nil
	}, false)
	if err != nil {
		return Out[apitypes.LicensesAssignManyOutput]{}, err
	}
	return Out[apitypes.LicensesAssignManyOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// Configure is POST {basePath}/licenses/configure. Turns inactive-seat reclaim and waiting-list email on or off for the tenant.
func (api *LicensesAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesConfigureInput]) (Out[apitypes.LicensesConfigureOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:manage", "licenses/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := licenseWritable(realm); err != nil {
			return nil, err
		}
		reclaim, notify := input.Get("reclaimAfterDays"), input.Get("notifyWaiting")
		if isUndefined(reclaim) && isUndefined(notify) {
			return nil, invalidInput("Nothing to update")
		}
		if _, isBool := notify.(bool); !isUndefined(notify) && !isBool {
			return nil, invalidInput("notifyWaiting must be a boolean")
		}
		stored, err := tx.Get(ctx, LicenseCollections.Settings, realmID)
		if err != nil {
			return nil, err
		}
		storedReclaim := any(core.Undefined)
		storedNotify := false
		if stored != nil {
			storedReclaim = stored.Get("reclaimAfterDays")
			storedNotify = stored.Get("notifyWaiting") == true
		}
		reclaimAfterDays := any(core.Undefined)
		switch {
		case isUndefined(reclaim):
			reclaimAfterDays = storedReclaim
		case reclaim == nil:
		default:
			days, err := Integer(reclaim, "reclaimAfterDays", LicenseReclaimDays.Min, LicenseReclaimDays.Max)
			if err != nil {
				return nil, err
			}
			reclaimAfterDays = days
		}
		next := core.NewObject("id", realmID, "tenantId", realmID)
		if !isUndefined(reclaimAfterDays) {
			next.Set("reclaimAfterDays", reclaimAfterDays)
		}
		next.Set("notifyWaiting", coalesce(notify, storedNotify))
		next.Set("updatedAt", float64(server.Now()))
		next.Set("updatedBy", principal.Identity.Get("id"))
		if stored != nil {
			_, err = tx.Put(ctx, LicenseCollections.Settings, next)
		} else {
			_, err = tx.Insert(ctx, LicenseCollections.Settings, next)
		}
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "license:settings", realmID, "licenses/settings", core.NewObject(
			"reclaimAfterDays", nullable(next.Get("reclaimAfterDays")),
			"notifyWaiting", next.Get("notifyWaiting"),
			"previousReclaimAfterDays", nullable(storedReclaim),
			"previousNotifyWaiting", storedNotify,
		)); err != nil {
			return nil, err
		}
		settings, err := ResolveLicenseSettings(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		return core.NewObject("tenantId", realmID).Assign(settings), nil
	}, false)
	return Out[apitypes.LicensesConfigureOutput]{Value: result}, err
}

// CreateProduct is POST {basePath}/licenses/createProduct. Defines a product: a permanent key, a name, and the feature keys a seat unlocks.
func (api *LicensesAPI) CreateProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesCreateProductInput]) (Out[apitypes.LicensesCreateProductOutput], error) {
	server := api.server
	key, err := LicenseKey(input.Get("key"))
	if err != nil {
		return Out[apitypes.LicensesCreateProductOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:manage", "licenses/products", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := licenseWritable(realm); err != nil {
			return nil, err
		}
		if err := api.platformGuard(ctx, tx, realm, principal); err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name", 100)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(name)
		description, err := licenseOptionalText(input.Get("description"), "description", 512)
		if err != nil {
			return nil, err
		}
		featureKeys, err := licenseFeatureKeysOf(coalesce(input.Get("featureKeys"), []any{}))
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		for _, ancestor := range chain[1:] {
			found, err := tx.Find(ctx, LicenseCollections.Products, core.NewObject("tenantId", ancestor.Get("id"), "uniqueKey", "key:"+key), nil)
			if err != nil {
				return nil, err
			}
			if len(found) > 0 {
				message := "An enclosing tenant already defines a license product with this key"
				if ancestor.Has("parentId") && ancestor.Get("parentId") == nil {
					message = "A platform license product already uses this key"
				}
				return nil, core.NewIamError("CONFLICT", message, 409)
			}
		}
		existing, err := tx.Find(ctx, LicenseCollections.Products, core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		for _, product := range existing {
			if product.Get("key") == key {
				return nil, core.NewIamError("CONFLICT", "A license product with this key already exists", 409)
			}
		}
		if len(existing) >= MaxLicenseProductsPerTenant {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can define at most "+core.NumberString(MaxLicenseProductsPerTenant)+" license products", 409)
		}
		now := float64(server.Now())
		record := core.NewObject("id", ID(), "tenantId", realmID, "uniqueKey", "key:"+key, "key", key, "name", name)
		if !isUndefined(description) {
			record.Set("description", description)
		}
		record.Set("featureKeys", featureKeys)
		record.Set("status", "active")
		record.Set("createdAt", now)
		record.Set("createdBy", principal.Identity.Get("id"))
		record.Set("updatedAt", now)
		record.Set("updatedBy", principal.Identity.Get("id"))
		product, err := tx.Insert(ctx, LicenseCollections.Products, record)
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "license:product-create", realmID, licenseProductResource(licenseString(product, "id")), licenseProductMetadata(product)); err != nil {
			return nil, err
		}
		return licenseProductViews([]*core.Object{product}, chain, realmID)[0], nil
	}, false)
	return Out[apitypes.LicensesCreateProductOutput]{Value: result}, err
}

// GetProduct is POST {basePath}/licenses/getProduct. Returns one product visible to the tenant, with where it is defined and whether it is shadowed.
func (api *LicensesAPI) GetProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesGetProductInput]) (Out[apitypes.LicensesGetProductOutput], error) {
	productID, err := Text(input.Get("productId"), "productId")
	if err != nil {
		return Out[apitypes.LicensesGetProductOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", licenseProductResource(productID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		product, chain, err := api.visibleProduct(ctx, call.Tx, call.Tenant, productID)
		if err != nil {
			return nil, err
		}
		return api.viewOf(ctx, call.Tx, call.Tenant, product, chain)
	}, false)
	return Out[apitypes.LicensesGetProductOutput]{Value: result}, err
}

// GetSettings is POST {basePath}/licenses/getSettings. Returns the tenant's license settings, with the defaults when they were never configured.
func (api *LicensesAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesGetSettingsInput]) (Out[apitypes.LicensesGetSettingsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		realmID := licenseString(call.Tenant, "id")
		settings, err := ResolveLicenseSettings(ctx, call.Tx, realmID)
		if err != nil {
			return nil, err
		}
		return core.NewObject("tenantId", realmID).Assign(settings), nil
	}, false)
	return Out[apitypes.LicensesGetSettingsOutput]{Value: result}, err
}

// ListAssignments is POST {basePath}/licenses/listAssignments. Lists the tenant's assignments, newest first, optionally of one product or subject.
func (api *LicensesAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListAssignmentsInput]) (Out[apitypes.LicensesListAssignmentsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/assignments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		limit, offset, err := licensePaging(input)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", call.Tenant.Get("id"))
		if !isUndefined(input.Get("productId")) {
			productID, err := Text(input.Get("productId"), "productId")
			if err != nil {
				return nil, err
			}
			filter.Set("productId", productID)
		}
		if !isUndefined(input.Get("subjectType")) {
			kind, err := licenseSubjectType(input.Get("subjectType"))
			if err != nil {
				return nil, err
			}
			filter.Set("subjectType", kind)
		}
		if !isUndefined(input.Get("subjectId")) {
			subjectID, err := Text(input.Get("subjectId"), "subjectId")
			if err != nil {
				return nil, err
			}
			filter.Set("subjectId", subjectID)
		}
		rows, err := tx.Find(ctx, LicenseCollections.Assignments, filter, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(rows, func(i, j int) bool {
			a, b := rows[i], rows[j]
			if difference := jsNumber(b.Get("assignedAt")) - jsNumber(a.Get("assignedAt")); difference != 0 {
				return difference < 0
			}
			return licenseByText(licenseString(a, "id"), licenseString(b, "id")) < 0
		})
		products := newLicenseCache(tx, LicenseCollections.Products)
		assignments := []any{}
		for _, assignment := range licensePage(rows, offset, limit) {
			product, err := products.get(ctx, licenseString(assignment, "productId"))
			if err != nil {
				return nil, err
			}
			key, name := licenseNames(product, assignment.Get("productId"))
			view, err := licenseAssignmentView(ctx, tx, assignment, key, name)
			if err != nil {
				return nil, err
			}
			assignments = append(assignments, view)
		}
		return core.NewObject("assignments", assignments, "total", float64(len(rows))), nil
	}, false)
	return Out[apitypes.LicensesListAssignmentsOutput]{Value: result}, err
}

// ListPools is POST {basePath}/licenses/listPools. Lists the tenant's pools and, for products it defines, the pools it granted to tenants below it, newest first.
func (api *LicensesAPI) ListPools(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListPoolsInput]) (Out[apitypes.LicensesListPoolsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/pools", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm := call.Tx, call.Tenant
		realmID := licenseString(realm, "id")
		limit, offset, err := licensePaging(input)
		if err != nil {
			return nil, err
		}
		var productID *string
		if !isUndefined(input.Get("productId")) {
			id, err := Text(input.Get("productId"), "productId")
			if err != nil {
				return nil, err
			}
			productID = &id
		}
		includeEnded := input.Get("includeEnded")
		if _, isBool := includeEnded.(bool); !isUndefined(includeEnded) && !isBool {
			return nil, invalidInput("includeEnded must be a boolean")
		}
		now := float64(server.Now())
		filter := core.NewObject("tenantId", realmID)
		if productID != nil {
			filter.Set("productId", *productID)
		}
		rows, err := tx.Find(ctx, LicenseCollections.Pools, filter, nil)
		if err != nil {
			return nil, err
		}
		owned, err := tx.Find(ctx, LicenseCollections.Products, core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		for _, product := range owned {
			if productID == nil || product.Get("id") == *productID {
				granted, err := tx.Find(ctx, LicenseCollections.Pools, core.NewObject("productId", product.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				for _, pool := range granted {
					if pool.Get("tenantId") != realmID {
						rows = append(rows, pool)
					}
				}
			}
		}
		shown := []*core.Object{}
		for _, pool := range rows {
			endsAt := pool.Get("endsAt")
			if includeEnded == true || isUndefined(endsAt) || jsNumber(endsAt) > now {
				shown = append(shown, pool)
			}
		}
		sort.SliceStable(shown, func(i, j int) bool {
			a, b := shown[i], shown[j]
			if difference := jsNumber(b.Get("createdAt")) - jsNumber(a.Get("createdAt")); difference != 0 {
				return difference < 0
			}
			return licenseByText(licenseString(a, "id"), licenseString(b, "id")) < 0
		})
		products := newLicenseCache(tx, LicenseCollections.Products)
		tenants := newLicenseCache(tx, "tenants")
		pools := []any{}
		for _, pool := range licensePage(shown, offset, limit) {
			owner, err := products.get(ctx, licenseString(pool, "productId"))
			if err != nil {
				return nil, err
			}
			key, name := licenseNames(owner, pool.Get("productId"))
			tenant, err := tenants.get(ctx, licenseString(pool, "tenantId"))
			if err != nil {
				return nil, err
			}
			tenantName := pool.Get("tenantId")
			if tenant != nil && !nullish(tenant.Get("name")) {
				tenantName = tenant.Get("name")
			}
			pools = append(pools, licensePoolView(pool, key, name, tenantName, now))
		}
		return core.NewObject("pools", pools, "total", float64(len(shown))), nil
	}, false)
	return Out[apitypes.LicensesListPoolsOutput]{Value: result}, err
}

// ListProducts is POST {basePath}/licenses/listProducts. Lists the products the tenant can use, its own and its ancestors', sorted by key.
func (api *LicensesAPI) ListProducts(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListProductsInput]) (Out[apitypes.LicensesListProductsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/products", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm := call.Tx, call.Tenant
		realmID := licenseString(realm, "id")
		status := input.Get("status")
		if !isUndefined(status) {
			if text, ok := status.(string); !ok || !licenseProductStatuses.Has(text) {
				return nil, invalidInput("status must be 'active' or 'retired'")
			}
		}
		chain, err := api.server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		depth := map[string]int{}
		for index, link := range chain {
			depth[licenseString(link, "id")] = index
		}
		products, err := VisibleLicenseProducts(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		views := []*core.Object{}
		for _, view := range licenseProductViews(products, chain, realmID) {
			if isUndefined(status) || view.Get("status") == status {
				views = append(views, view)
			}
		}
		sort.SliceStable(views, func(i, j int) bool {
			a, b := views[i], views[j]
			if order := licenseByText(licenseString(a, "key"), licenseString(b, "key")); order != 0 {
				return order < 0
			}
			return depth[licenseString(b, "definedBy")]-depth[licenseString(a, "definedBy")] < 0
		})
		list := make([]any, len(views))
		for index, view := range views {
			list[index] = view
		}
		return core.NewObject("tenantId", realmID, "products", list), nil
	}, false)
	return Out[apitypes.LicensesListProductsOutput]{Value: result}, err
}

// ListSeats is POST {basePath}/licenses/listSeats. Lists the tenant's seats: who holds each product and who waits, in order.
func (api *LicensesAPI) ListSeats(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListSeatsInput]) (Out[apitypes.LicensesListSeatsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/seats", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm := call.Tx, call.Tenant
		limit, offset, err := licensePaging(input)
		if err != nil {
			return nil, err
		}
		status := input.Get("status")
		if !isUndefined(status) {
			if text, ok := status.(string); !ok || !licenseSeatStatuses.Has(text) {
				return nil, invalidInput("status must be 'active' or 'waiting'")
			}
		}
		var identityID *string
		if !isUndefined(input.Get("identityId")) {
			id, err := Text(input.Get("identityId"), "identityId")
			if err != nil {
				return nil, err
			}
			identityID = &id
		}
		filter := core.NewObject("tenantId", realm.Get("id"))
		if !isUndefined(input.Get("productId")) {
			productID, err := Text(input.Get("productId"), "productId")
			if err != nil {
				return nil, err
			}
			filter.Set("productId", productID)
		}
		all, err := tx.Find(ctx, LicenseCollections.Seats, filter, nil)
		if err != nil {
			return nil, err
		}
		positions := licenseWaitingPositions(all)
		products := newLicenseCache(tx, LicenseCollections.Products)
		keys := map[string]string{}
		for _, seat := range all {
			productID := licenseString(seat, "productId")
			if _, ok := keys[productID]; !ok {
				product, err := products.get(ctx, productID)
				if err != nil {
					return nil, err
				}
				keys[productID] = productID
				if product != nil && !nullish(product.Get("key")) {
					keys[productID] = licenseString(product, "key")
				}
			}
		}
		rows := []*core.Object{}
		for _, seat := range all {
			if (isUndefined(status) || seat.Get("status") == status) && (identityID == nil || seat.Get("identityId") == *identityID) {
				rows = append(rows, seat)
			}
		}
		waitingFlag := func(seat *core.Object) int {
			if seat.Get("status") == "waiting" {
				return 1
			}
			return 0
		}
		sort.SliceStable(rows, func(i, j int) bool {
			a, b := rows[i], rows[j]
			if order := licenseByText(keys[licenseString(a, "productId")], keys[licenseString(b, "productId")]); order != 0 {
				return order < 0
			}
			if order := licenseByText(licenseString(a, "productId"), licenseString(b, "productId")); order != 0 {
				return order < 0
			}
			if difference := waitingFlag(a) - waitingFlag(b); difference != 0 {
				return difference < 0
			}
			if difference := jsNumber(a.Get("assignedAt")) - jsNumber(b.Get("assignedAt")); difference != 0 {
				return difference < 0
			}
			return licenseByText(licenseString(a, "identityId"), licenseString(b, "identityId")) < 0
		})
		seats := []any{}
		for _, seat := range licensePage(rows, offset, limit) {
			owner, err := products.get(ctx, licenseString(seat, "productId"))
			if err != nil {
				return nil, err
			}
			holder, err := tx.Get(ctx, "identities", licenseString(seat, "identityId"))
			if err != nil {
				return nil, err
			}
			productKey, productName := seat.Get("productId"), seat.Get("productId")
			if owner != nil {
				productKey = coalesce(owner.Get("key"), seat.Get("productId"))
				productName = coalesce(owner.Get("name"), seat.Get("productId"))
			}
			view := core.NewObject(
				"id", seat.Get("id"),
				"tenantId", seat.Get("tenantId"),
				"productId", seat.Get("productId"),
				"productKey", productKey,
				"productName", productName,
				"identityId", seat.Get("identityId"),
			)
			if holder != nil {
				view.Set("identityName", coalesce(holder.Get("name"), seat.Get("identityId")))
				if !isUndefined(holder.Get("email")) {
					view.Set("identityEmail", holder.Get("email"))
				}
				view.Set("identityKind", holder.Get("kind"))
			} else {
				view.Set("identityName", seat.Get("identityId"))
			}
			view.Set("status", seat.Get("status"))
			if position, ok := positions[licenseString(seat, "id")]; ok {
				view.Set("position", float64(position))
			}
			view.Set("direct", licenseSeatDirect(seat))
			view.Set("groupIds", stringsOf(licenseSeatGroups(seat)))
			view.Set("assignedAt", seat.Get("assignedAt"))
			if !isUndefined(seat.Get("activatedAt")) {
				view.Set("activatedAt", seat.Get("activatedAt"))
			}
			if !isUndefined(seat.Get("lastActivityAt")) {
				view.Set("lastActivityAt", seat.Get("lastActivityAt"))
			}
			seats = append(seats, view)
		}
		return core.NewObject("seats", seats, "total", float64(len(rows))), nil
	}, false)
	return Out[apitypes.LicensesListSeatsOutput]{Value: result}, err
}

// Mine is POST {basePath}/licenses/mine. Returns the caller's own licenses in the tenant, waiting-list places included, and the feature keys they unlock.
func (api *LicensesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesMineInput]) (Out[apitypes.LicensesMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.LicensesMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.LicensesMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		realmID := licenseString(realm, "id")
		if principal.Session.Get("tenantId") != realmID {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "Licenses are read from a session of their tenant", 403)
			}
		}
		identity := principal.Identity
		empty := func() *core.Object {
			return core.NewObject("tenantId", realmID, "identityId", identity.Get("id"), "licenses", []any{},
				"featureKeys", []any{}, "allFeatureKeys", []any{})
		}
		if principal.Session.Get("kind") == "role" || identity.Get("tenantId") != realmID {
			return empty(), nil
		}
		now := server.Now()
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		rootID := chain[len(chain)-1].Get("id")
		identityID := licenseString(identity, "id")
		held, err := HeldLicenses(ctx, tx, realmID, identityID, now)
		if err != nil {
			return nil, err
		}
		counted := newOrderedSet()
		for _, entry := range held {
			counted.Add(jsString(member(entry.Get("seat"), "id")))
		}
		type myLicense struct {
			view      *core.Object
			key       string
			productID string
			platform  bool
			features  []any
		}
		licenses := []myLicense{}
		// A shadowed product, or one the tenant no longer sees, grants nothing: neither its seats nor its waiting list.
		granting, err := GrantingLicenseProducts(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", realmID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, seat := range seats {
			product := granting[licenseString(seat, "productId")]
			if product == nil || product.Get("status") != "active" {
				continue
			}
			if seat.Get("status") == "active" && !counted.Has(licenseString(seat, "id")) {
				continue
			}
			position := 0
			if seat.Get("status") == "waiting" {
				queue, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", realmID, "productId", seat.Get("productId"), "status", "waiting"), nil)
				if err != nil {
					return nil, err
				}
				position = licenseWaitingPositions(queue)[licenseString(seat, "id")]
			}
			features := []any{}
			if seat.Get("status") == "active" {
				features, _ = product.Get("featureKeys").([]any)
			}
			view := core.NewObject("productId", product.Get("id"), "key", product.Get("key"), "name", product.Get("name"))
			if !isUndefined(product.Get("description")) {
				view.Set("description", product.Get("description"))
			}
			view.Set("status", seat.Get("status"))
			if position != 0 {
				view.Set("position", float64(position))
			}
			platform := product.Get("tenantId") == rootID
			if seat.Get("status") == "active" {
				view.Set("featureKeys", product.Get("featureKeys"))
			} else {
				view.Set("featureKeys", []any{})
			}
			view.Set("platform", platform)
			view.Set("definedBy", product.Get("tenantId"))
			licenses = append(licenses, myLicense{view: view, key: licenseString(product, "key"), productID: licenseString(product, "id"), platform: platform, features: features})
		}
		sort.SliceStable(licenses, func(i, j int) bool {
			if order := licenseByText(licenses[i].key, licenses[j].key); order != 0 {
				return order < 0
			}
			return licenseByText(licenses[i].productID, licenses[j].productID) < 0
		})
		union := func(platformOnly bool) []any {
			keys := newOrderedSet()
			for _, license := range licenses {
				if platformOnly && !license.platform {
					continue
				}
				for _, key := range license.features {
					keys.Add(jsString(key))
				}
			}
			values := keys.Values()
			sortStrings(values)
			return stringsOf(values)
		}
		list := make([]any, len(licenses))
		for index, license := range licenses {
			list[index] = license.view
		}
		answer := empty()
		answer.Set("licenses", list)
		// Only the platform's products are paid entitlements no tenant can mint for itself.
		answer.Set("featureKeys", union(true))
		answer.Set("allFeatureKeys", union(false))
		return answer, nil
	})
	return Out[apitypes.LicensesMineOutput]{Value: result}, err
}

// RemovePool is POST {basePath}/licenses/removePool. Removes a pool; the newest active seats beyond the remaining capacity move to the waiting list.
func (api *LicensesAPI) RemovePool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesRemovePoolInput]) (Out[apitypes.LicensesRemovePoolOutput], error) {
	server := api.server
	poolID, err := Text(input.Get("poolId"), "poolId")
	if err != nil {
		return Out[apitypes.LicensesRemovePoolOutput]{}, err
	}
	authority, platform, err := api.poolAuthorityOf(ctx, poolID, input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.LicensesRemovePoolOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, authority, "iam:licenses:manage", licensePoolResource(poolID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, definer, principal := call.Tx, call.Tenant, call.Principal
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		pool, err := server.Scoped(ctx, tx, LicenseCollections.Pools, poolID, tenantID)
		if err != nil {
			return nil, err
		}
		// A tenant that moved away keeps no hold on capacity the definer granted it.
		product, consumer, err := api.poolTarget(ctx, tx, definer, pool.Get("tenantId"), licenseString(pool, "productId"), true)
		if err != nil {
			return nil, err
		}
		verifyConsumer, err := api.consumerInvariants(ctx, tx, definer, consumer)
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, LicenseCollections.Pools, licenseString(pool, "id")); err != nil {
			return nil, err
		}
		consumerID := licenseString(consumer, "id")
		if err := api.audit(ctx, tx, principal, "license:pool-remove", consumerID, licensePoolResource(licenseString(pool, "id")), licensePoolMetadata(pool, product)); err != nil {
			return nil, err
		}
		productID := licenseString(product, "id")
		seats, err := reconcileLicenses(ctx, server, tx, consumerID, &productID, principal, "pool-remove")
		if err != nil {
			return nil, err
		}
		if err := verifyConsumer(); err != nil {
			return nil, err
		}
		return core.NewObject("removed", true, "seats", licenseChanges(seats)), nil
	}, platform)
	if err != nil {
		return Out[apitypes.LicensesRemovePoolOutput]{}, err
	}
	return Out[apitypes.LicensesRemovePoolOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// poolAuthorityOf picks the authorizing tenant of a change to an existing pool: the pool's product's definer when the
// pool belongs to the named tenant.
func (api *LicensesAPI) poolAuthorityOf(ctx context.Context, poolID string, tenantID any) (any, bool, error) {
	found, err := api.server.Store.Get(ctx, LicenseCollections.Pools, poolID)
	if err != nil {
		return nil, false, err
	}
	var productID *string
	if found != nil && found.Get("tenantId") == tenantID {
		id := licenseString(found, "productId")
		productID = &id
	}
	return api.poolAuthority(ctx, productID, tenantID)
}

// RetireProduct is POST {basePath}/licenses/retireProduct. Retires a product for good, releasing its seats in every tenant.
func (api *LicensesAPI) RetireProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesRetireProductInput]) (Out[apitypes.LicensesRetireProductOutput], error) {
	server := api.server
	productID, err := Text(input.Get("productId"), "productId")
	if err != nil {
		return Out[apitypes.LicensesRetireProductOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:manage", licenseProductResource(productID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		product, chain, err := api.ownProduct(ctx, tx, realm, productID)
		if err != nil {
			return nil, err
		}
		if err := api.platformGuard(ctx, tx, realm, principal); err != nil {
			return nil, err
		}
		if product.Get("status") == "retired" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The product is already retired", 409)
		}
		next, err := tx.Put(ctx, LicenseCollections.Products, product.Spread(core.NewObject(
			"status", "retired",
			"updatedAt", float64(server.Now()),
			"updatedBy", principal.Identity.Get("id"),
		)))
		if err != nil {
			return nil, err
		}
		held, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("productId", product.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		tenants := newOrderedSet()
		for _, seat := range held {
			tenants.Add(licenseString(seat, "tenantId"))
		}
		tenantIDs := tenants.Values()
		sortStrings(tenantIDs)
		id := licenseString(product, "id")
		seats := []*core.Object{}
		for _, tenantID := range tenantIDs {
			changes, err := reconcileLicenses(ctx, server, tx, tenantID, &id, principal, "product-retired")
			if err != nil {
				return nil, err
			}
			seats = append(seats, changes...)
		}
		if err := api.audit(ctx, tx, principal, "license:product-retire", realmID, licenseProductResource(licenseString(next, "id")), core.NewObject(
			"productId", next.Get("id"),
			"key", next.Get("key"),
			"releasedSeats", float64(len(seats)),
			"tenants", float64(len(tenantIDs)),
		)); err != nil {
			return nil, err
		}
		view, err := api.viewOf(ctx, tx, realm, next, chain)
		if err != nil {
			return nil, err
		}
		return core.NewObject("product", view, "seats", licenseChanges(seats)), nil
	}, false)
	if err != nil {
		return Out[apitypes.LicensesRetireProductOutput]{}, err
	}
	return Out[apitypes.LicensesRetireProductOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// Unassign is POST {basePath}/licenses/unassign. Removes an assignment; seats it carried are released unless another assignment still covers the person.
func (api *LicensesAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUnassignInput]) (Out[apitypes.LicensesUnassignOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:assign", "licenses/assignments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		var assignment *core.Object
		if !isUndefined(input.Get("assignmentId")) {
			found, err := server.Scoped(ctx, tx, LicenseCollections.Assignments, input.Get("assignmentId"), realmID)
			if err != nil {
				return nil, err
			}
			assignment = found
		} else {
			productID, err := Text(input.Get("productId"), "productId")
			if err != nil {
				return nil, err
			}
			kind, err := licenseSubjectType(input.Get("subjectType"))
			if err != nil {
				return nil, err
			}
			subjectID, err := Text(input.Get("subjectId"), "subjectId")
			if err != nil {
				return nil, err
			}
			found, err := tx.Find(ctx, LicenseCollections.Assignments, core.NewObject("tenantId", realmID, "uniqueKey", productID+":"+kind+":"+subjectID), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, core.NewIamError("NOT_FOUND", "Assignment not found", 404)
			}
			assignment = found[0]
		}
		if err := tx.Delete(ctx, LicenseCollections.Assignments, licenseString(assignment, "id")); err != nil {
			return nil, err
		}
		productID := licenseString(assignment, "productId")
		product, err := tx.Get(ctx, LicenseCollections.Products, productID)
		if err != nil {
			return nil, err
		}
		productKey, _ := licenseNames(product, assignment.Get("productId"))
		if err := api.audit(ctx, tx, principal, "license:unassign", realmID, licenseString(assignment, "subjectId"), core.NewObject(
			"assignmentId", assignment.Get("id"),
			"productId", assignment.Get("productId"),
			"productKey", coalesce(productKey, assignment.Get("productId")),
			"subjectType", assignment.Get("subjectType"),
		)); err != nil {
			return nil, err
		}
		seats, err := reconcileLicenses(ctx, server, tx, realmID, &productID, principal, "unassign")
		if err != nil {
			return nil, err
		}
		return core.NewObject("removed", true, "seats", licenseChanges(seats)), nil
	}, false)
	if err != nil {
		return Out[apitypes.LicensesUnassignOutput]{}, err
	}
	return Out[apitypes.LicensesUnassignOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// UpdatePool is POST {basePath}/licenses/updatePool. Changes a pool's quantity, its end, or its note; seats follow the new capacity at once.
func (api *LicensesAPI) UpdatePool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUpdatePoolInput]) (Out[apitypes.LicensesUpdatePoolOutput], error) {
	server := api.server
	poolID, err := Text(input.Get("poolId"), "poolId")
	if err != nil {
		return Out[apitypes.LicensesUpdatePoolOutput]{}, err
	}
	authority, platform, err := api.poolAuthorityOf(ctx, poolID, input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.LicensesUpdatePoolOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, authority, "iam:licenses:manage", licensePoolResource(poolID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, definer, principal := call.Tx, call.Tenant, call.Principal
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		pool, err := server.Scoped(ctx, tx, LicenseCollections.Pools, poolID, tenantID)
		if err != nil {
			return nil, err
		}
		product, consumer, err := api.poolTarget(ctx, tx, definer, pool.Get("tenantId"), licenseString(pool, "productId"), false)
		if err != nil {
			return nil, err
		}
		quantityInput, endsAtInput, noteInput := input.Get("quantity"), input.Get("endsAt"), input.Get("note")
		if isUndefined(quantityInput) && isUndefined(endsAtInput) && isUndefined(noteInput) {
			return nil, invalidInput("Nothing to update")
		}
		rest := pool.Spread()
		rest.Delete("endsAt")
		rest.Delete("expiresAt")
		rest.Delete("note")
		endsAt := any(core.Undefined)
		switch {
		case isUndefined(endsAtInput):
			endsAt = pool.Get("endsAt")
		case endsAtInput == nil:
		default:
			if endsAt, err = licenseTimestamp(endsAtInput, "endsAt"); err != nil {
				return nil, err
			}
		}
		if startsAt := pool.Get("startsAt"); !isUndefined(endsAt) && !isUndefined(startsAt) && jsNumber(endsAt) <= jsNumber(startsAt) {
			return nil, invalidInput("endsAt must be after startsAt")
		}
		note := any(core.Undefined)
		switch {
		case isUndefined(noteInput):
			note = pool.Get("note")
		case noteInput == nil:
		default:
			text, err := Text(noteInput, "note", 512)
			if err != nil {
				return nil, err
			}
			note = core.JSTrim(text)
		}
		verifyConsumer, err := api.consumerInvariants(ctx, tx, definer, consumer)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		quantity := pool.Get("quantity")
		if !isUndefined(quantityInput) {
			if quantity, err = Integer(quantityInput, "quantity", 1, MaxLicensePoolQuantity); err != nil {
				return nil, err
			}
		}
		rest.Set("quantity", quantity)
		if !isUndefined(endsAt) {
			rest.Set("endsAt", endsAt)
			rest.Set("expiresAt", jsNumber(endsAt)+LicensePoolRetentionMs)
		}
		if !isUndefined(note) {
			rest.Set("note", note)
		}
		rest.Set("updatedAt", now)
		rest.Set("updatedBy", principal.Identity.Get("id"))
		next, err := tx.Put(ctx, LicenseCollections.Pools, rest)
		if err != nil {
			return nil, err
		}
		consumerID := licenseString(consumer, "id")
		if err := api.audit(ctx, tx, principal, "license:pool-update", consumerID, licensePoolResource(licenseString(pool, "id")), core.NewObject(
			"before", licensePoolMetadata(pool, product),
			"after", licensePoolMetadata(next, product),
		)); err != nil {
			return nil, err
		}
		productID := licenseString(product, "id")
		seats, err := reconcileLicenses(ctx, server, tx, consumerID, &productID, principal, "pool-update")
		if err != nil {
			return nil, err
		}
		if err := verifyConsumer(); err != nil {
			return nil, err
		}
		return core.NewObject(
			"pool", licensePoolView(next, product.Get("key"), product.Get("name"), consumer.Get("name"), now),
			"seats", licenseChanges(seats),
		), nil
	}, platform)
	if err != nil {
		return Out[apitypes.LicensesUpdatePoolOutput]{}, err
	}
	return Out[apitypes.LicensesUpdatePoolOutput]{Value: licenseFollowResult(ctx, server, result)}, nil
}

// UpdateProduct is POST {basePath}/licenses/updateProduct. Renames a product, changes its description, or replaces its feature keys; the key never changes.
func (api *LicensesAPI) UpdateProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUpdateProductInput]) (Out[apitypes.LicensesUpdateProductOutput], error) {
	server := api.server
	productID, err := Text(input.Get("productId"), "productId")
	if err != nil {
		return Out[apitypes.LicensesUpdateProductOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:manage", licenseProductResource(productID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm, principal := call.Tx, call.Tenant, call.Principal
		realmID := licenseString(realm, "id")
		if err := licenseWritable(realm); err != nil {
			return nil, err
		}
		product, chain, err := api.ownProduct(ctx, tx, realm, productID)
		if err != nil {
			return nil, err
		}
		if err := api.platformGuard(ctx, tx, realm, principal); err != nil {
			return nil, err
		}
		nameInput, descriptionInput, featureKeysInput := input.Get("name"), input.Get("description"), input.Get("featureKeys")
		if isUndefined(nameInput) && isUndefined(descriptionInput) && isUndefined(featureKeysInput) {
			return nil, invalidInput("Nothing to update")
		}
		rest := product.Spread()
		rest.Delete("description")
		description := any(core.Undefined)
		switch {
		case isUndefined(descriptionInput):
			description = product.Get("description")
		case descriptionInput == nil:
		default:
			text, err := Text(descriptionInput, "description", 512)
			if err != nil {
				return nil, err
			}
			description = core.JSTrim(text)
		}
		if !isUndefined(nameInput) {
			name, err := Text(nameInput, "name", 100)
			if err != nil {
				return nil, err
			}
			rest.Set("name", core.JSTrim(name))
		}
		if !isUndefined(description) {
			rest.Set("description", description)
		}
		if !isUndefined(featureKeysInput) {
			featureKeys, err := licenseFeatureKeysOf(featureKeysInput)
			if err != nil {
				return nil, err
			}
			rest.Set("featureKeys", featureKeys)
		}
		rest.Set("updatedAt", float64(server.Now()))
		rest.Set("updatedBy", principal.Identity.Get("id"))
		next, err := tx.Put(ctx, LicenseCollections.Products, rest)
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "license:product-update", realmID, licenseProductResource(licenseString(next, "id")), core.NewObject(
			"before", licenseProductMetadata(product),
			"after", licenseProductMetadata(next),
		)); err != nil {
			return nil, err
		}
		return api.viewOf(ctx, tx, realm, next, chain)
	}, false)
	return Out[apitypes.LicensesUpdateProductOutput]{Value: result}, err
}

// Usage is POST {basePath}/licenses/usage. Reports, per product the tenant uses, its capacity and how many seats are active, waiting, available, and reclaimable.
func (api *LicensesAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUsageInput]) (Out[apitypes.LicensesUsageOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:licenses:read", "licenses/seats", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, realm := call.Tx, call.Tenant
		realmID := licenseString(realm, "id")
		now := float64(server.Now())
		chain, err := server.Ancestry(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		rootID := chain[len(chain)-1].Get("id")
		settings, err := ResolveLicenseSettings(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		reclaimAfterDays := settings.Get("reclaimAfterDays")
		var cutoff *float64
		if !isUndefined(reclaimAfterDays) {
			value := now - jsNumber(reclaimAfterDays)*licenseDay
			cutoff = &value
		}
		filter := core.NewObject("tenantId", realmID)
		pools, err := tx.Find(ctx, LicenseCollections.Pools, filter, nil)
		if err != nil {
			return nil, err
		}
		seats, err := tx.Find(ctx, LicenseCollections.Seats, filter, nil)
		if err != nil {
			return nil, err
		}
		assignments, err := tx.Find(ctx, LicenseCollections.Assignments, filter, nil)
		if err != nil {
			return nil, err
		}
		used := newOrderedSet()
		for _, group := range [][]*core.Object{pools, seats, assignments} {
			for _, record := range group {
				used.Add(licenseString(record, "productId"))
			}
		}
		activity := map[string]*float64{}
		inactive := func(seat *core.Object) (bool, error) {
			if cutoff == nil || seat.Get("status") != "active" || jsNumber(seat.Get("assignedAt")) > *cutoff {
				return false, nil
			}
			identityID := licenseString(seat, "identityId")
			if _, ok := activity[identityID]; !ok {
				holder, err := tx.Get(ctx, "identities", identityID)
				if err != nil {
					return false, err
				}
				var last *float64
				if holder != nil {
					value, err := LastActivityOf(ctx, tx, holder)
					if err != nil {
						return false, err
					}
					last = &value
				}
				activity[identityID] = last
			}
			last := activity[identityID]
			return last != nil && *last <= *cutoff, nil
		}
		visible, err := VisibleLicenseProducts(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		type usage struct {
			view      *core.Object
			key       string
			productID string
		}
		products := []usage{}
		for _, product := range visible {
			productID := licenseString(product, "id")
			if !used.Has(productID) && product.Get("tenantId") != realmID {
				continue
			}
			own := []*core.Object{}
			for _, seat := range seats {
				if seat.Get("productId") == productID {
					own = append(own, seat)
				}
			}
			livePools := []*core.Object{}
			for _, pool := range pools {
				if pool.Get("productId") == productID && liveLicensePool(pool, now) {
					livePools = append(livePools, pool)
				}
			}
			capacity := licenseCapacity(livePools, now)
			active := 0
			for _, seat := range own {
				if seat.Get("status") == "active" {
					active++
				}
			}
			reclaimable, reclaimableThroughGroups := 0, 0
			for _, seat := range own {
				idle, err := inactive(seat)
				if err != nil {
					return nil, err
				}
				if idle {
					reclaimable++
					if !licenseSeatDirect(seat) {
						reclaimableThroughGroups++
					}
				}
			}
			assigned := 0
			for _, assignment := range assignments {
				if assignment.Get("productId") == productID {
					assigned++
				}
			}
			scope := "tenant"
			if product.Get("tenantId") == rootID {
				scope = "platform"
			}
			products = append(products, usage{key: licenseString(product, "key"), productID: productID, view: core.NewObject(
				"productId", product.Get("id"),
				"key", product.Get("key"),
				"name", product.Get("name"),
				"scope", scope,
				"status", product.Get("status"),
				"capacity", capacity,
				"active", float64(active),
				"waiting", float64(len(own)-active),
				"available", math.Max(0, capacity-float64(active)),
				"pools", float64(len(livePools)),
				"assignments", float64(assigned),
				"reclaimable", float64(reclaimable),
				"reclaimableThroughGroups", float64(reclaimableThroughGroups),
			)})
		}
		sort.SliceStable(products, func(i, j int) bool {
			if order := licenseByText(products[i].key, products[j].key); order != 0 {
				return order < 0
			}
			return licenseByText(products[i].productID, products[j].productID) < 0
		})
		list := make([]any, len(products))
		for index, entry := range products {
			list[index] = entry.view
		}
		report := core.NewObject("tenantId", realmID)
		if !isUndefined(reclaimAfterDays) {
			report.Set("reclaimAfterDays", reclaimAfterDays)
		}
		report.Set("products", list)
		return report, nil
	}, false)
	return Out[apitypes.LicensesUsageOutput]{Value: result}, err
}

// IamLicenses is api/licenses.ts IamLicenses.
type IamLicenses struct {
	server *ServerContext
}

// held is the seats that count for a person of the tenant (none for inactive, expired, or other tenants' people).
// With trust, only those of products defined by the trusted tenant or its ancestors: `trustedTenantId`, else the root
// tenant alone (platform products).
func (s *IamLicenses) held(ctx context.Context, identityID, tenantID string, trust bool, trustedTenantID any) ([]*core.Object, error) {
	server := s.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		var trusted *orderedSet
		if trust {
			trusted = newOrderedSet()
			if !isUndefined(trustedTenantID) {
				id, err := Text(trustedTenantID, "trustedTenantId")
				if err != nil {
					return nil, err
				}
				tenant, err := server.Tenant(ctx, tx, id)
				if err != nil {
					return nil, err
				}
				chain, err := server.Ancestry(ctx, tx, tenant)
				if err != nil {
					return nil, err
				}
				for _, link := range chain {
					trusted.Add(licenseString(link, "id"))
				}
			} else {
				chain, err := server.Ancestry(ctx, tx, realm)
				if err != nil {
					return nil, err
				}
				trusted.Add(licenseString(chain[len(chain)-1], "id"))
			}
		}
		id, err := Text(identityID, "identityId")
		if err != nil {
			return nil, err
		}
		identity, err := tx.Get(ctx, "identities", id)
		if err != nil {
			return nil, err
		}
		if identity == nil || identity.Get("tenantId") != realm.Get("id") || identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return []*core.Object{}, nil
		}
		seats, err := HeldLicenses(ctx, tx, licenseString(realm, "id"), licenseString(identity, "id"), server.Now())
		if err != nil {
			return nil, err
		}
		if trusted == nil {
			return seats, nil
		}
		kept := []*core.Object{}
		for _, seat := range seats {
			if trusted.Has(jsString(member(seat.Get("product"), "tenantId"))) {
				kept = append(kept, seat)
			}
		}
		return kept, nil
	})
}

// Features (api/licenses.ts IamLicenses.features): The feature keys of the products a person holds an active seat
// for in the tenant (none for inactive people), from the products the trusted tenant or one of its ancestors defines
// only. Any tenant can define a product of its own that lists any feature key, so by default only **platform**
// products (the root tenant's) count: pass `trustedTenantId` to count the products a tenant (and the tenants above
// it) sells too, such as the tenant's own.
func (s *IamLicenses) Features(ctx context.Context, identityID string, tenantID string, options *core.Object) (result []string, err error) {
	trustedTenantID := any(core.Undefined)
	if options != nil {
		trustedTenantID = options.Get("trustedTenantId")
	}
	held, err := s.held(ctx, identityID, tenantID, true, trustedTenantID)
	if err != nil {
		return nil, err
	}
	keys := newOrderedSet()
	for _, entry := range held {
		list, _ := member(entry.Get("product"), "featureKeys").([]any)
		for _, key := range list {
			keys.Add(jsString(key))
		}
	}
	values := keys.Values()
	sortStrings(values)
	if values == nil {
		values = []string{}
	}
	return values, nil
}

// Products (api/licenses.ts IamLicenses.products): The keys of the products a person holds an active seat for in the
// tenant: what `principal.licenses` holds.
func (s *IamLicenses) Products(ctx context.Context, identityID string, tenantID string) (result []string, err error) {
	held, err := s.held(ctx, identityID, tenantID, false, core.Undefined)
	if err != nil {
		return nil, err
	}
	keys := newOrderedSet()
	for _, entry := range held {
		keys.Add(heldKey(entry))
	}
	values := keys.Values()
	sortStrings(values)
	if values == nil {
		values = []string{}
	}
	return values, nil
}

// Reconcile (api/licenses.ts IamLicenses.reconcile): A scheduler job (hourly): brings every tenant's seats in line
// with assignments, memberships, identity status and pool terms, and re-evaluates birthright package rules for the
// people whose seats changed.
func (s *IamLicenses) Reconcile(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return ReconcileAllLicenses(ctx, s.server, input)
}

// Reclaim (api/licenses.ts IamLicenses.reclaim): A scheduler job (daily): in tenants with `reclaimAfterDays`,
// removes direct assignments of people with no sign-in or credential use for that long (audited `license:reclaim`),
// then reconciles.
func (s *IamLicenses) Reclaim(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return ReclaimLicenses(ctx, s.server, input)
}

// CreateLicensesRuntime builds the IamLicenses (api/licenses.ts createLicensesRuntime): credential-free license
// helpers and jobs, shared by `iam.licenses` and tests.
func CreateLicensesRuntime(server *ServerContext) *IamLicenses {
	return &IamLicenses{server: server}
}
