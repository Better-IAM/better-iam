package server

// Skeleton of packages/server/src/licenses.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// BatchGroupLicenses (licenses.ts batchGroupLicenses): Runs a batch of group membership writes (`groups.addMembers`,
// offboarding, configuration sync) with the seat reconciliation they cause deferred to the end of the batch, where
// each affected product is reconciled once instead of once per membership: every run rebuilds all of the product's
// claimants, which made batches quadratic inside the transaction. People who claim a seat in the same batch rank by
// identity ID among themselves. Nested batches join the outermost one.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BatchGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, run func(context.Context) (any, error)) (result any, err error) {
	err = notImplemented("licenses.ts batchGroupLicenses")
	return
}

// GrantingLicenseProducts (licenses.ts grantingLicenseProducts): The products whose seats grant their key in a
// tenant: those visible to it, except a product whose key a tenant enclosing its definer defines as well
// (`shadowed`). The definition closest to the root wins, so a tenant can never mint seats that count as a key the
// platform or an enclosing tenant sells, and a product of a tenant the seat's tenant is no longer below (after
// `tenants.reparent`) grants nothing there.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GrantingLicenseProducts(ctx context.Context, reader core.IamStore, tenantID string) (result map[string]*core.Object, err error) {
	err = notImplemented("licenses.ts grantingLicenseProducts")
	return
}

// GroupsHoldLicenses (licenses.ts groupsHoldLicenses): Whether a product that still holds seats (an active one) is
// assigned to any of the groups.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GroupsHoldLicenses(ctx context.Context, tx core.IamStore, tenantID string, groupIDs []string) (result bool, err error) {
	err = notImplemented("licenses.ts groupsHoldLicenses")
	return
}

// HeldLicenses (licenses.ts heldLicenses): The active seats of a person in a tenant that count right now: the
// product is active and grants its key in the tenant (`grantingLicenseProducts`: not shadowed by an enclosing
// tenant's product, still visible), and a seat held only through groups still has a live membership behind it
// (memberships lapse between reconciliations).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HeldLicenses(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts heldLicenses")
	return
}

// LastActivityOf (licenses.ts lastActivityOf): A person's latest activity: their last sign-in (`authSignIns`, else
// when the account was created) or the last use of one of their own sessions or API keys ("view as" sessions of
// administrators excluded).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LastActivityOf(ctx context.Context, tx core.IamStore, identity *core.Object) (result float64, err error) {
	err = notImplemented("licenses.ts lastActivityOf")
	return
}

// LicenseCapacity (licenses.ts licenseCapacity): The seats a set of pools provides at `now`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LicenseCapacity(pools []*core.Object, now int64) (result float64, err error) {
	err = notImplemented("licenses.ts licenseCapacity")
	return
}

// LicenseContext (licenses.ts licenseContext): `principal.licenses` for a person in their own tenant: the keys of
// the products they hold an active seat for.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LicenseContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64) (result *core.Object, err error) {
	err = notImplemented("licenses.ts licenseContext")
	return
}

// LicenseKey (licenses.ts licenseKey): Validates a product key: lowercase letters, digits, dots, underscores or
// hyphens, starting with a letter or digit.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LicenseKey(value any) (result string, err error) {
	err = notImplemented("licenses.ts licenseKey")
	return
}

// LicenseRuleKeys (licenses.ts licenseRuleKeys): The valid `identity.licenses` values of a tenant: the keys of every
// product visible to it, retired ones included.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LicenseRuleKeys(ctx context.Context, reader core.IamStore, tenantID string) (result []string, err error) {
	err = notImplemented("licenses.ts licenseRuleKeys")
	return
}

// LiveLicensePool (licenses.ts liveLicensePool): Whether a pool contributes capacity at `now`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveLicensePool(pool *core.Object, now int64) (result bool, err error) {
	err = notImplemented("licenses.ts liveLicensePool")
	return
}

// TenantLicenseFacts is licenses.ts TenantLicenseFacts.
type TenantLicenseFacts struct {
	server *ServerContext
	// Keys The keys of every product visible to the tenant.
	Keys []string
}

// Of (licenses.ts TenantLicenseFacts.of): The keys of the products a person holds an active seat for. A seat held
// only through groups counts while one of them is in `countedGroupIds` (memberships no access package created), so a
// rule never feeds on what a package granted.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TenantLicenseFacts) Of(identityID string, countedGroupIDs []string) (result []string, err error) {
	err = notImplemented("licenses.ts TenantLicenseFacts.of")
	return
}

// LoadLicenseFacts (licenses.ts loadLicenseFacts): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadLicenseFacts(ctx context.Context, reader core.IamStore, tenantID string) (result *TenantLicenseFacts, err error) {
	err = notImplemented("licenses.ts loadLicenseFacts")
	return
}

// MentionsLicenses (licenses.ts mentionsLicenses): whether any document names `principal.licenses` (conditions,
// `${…}` variables, resource patterns).
func MentionsLicenses(documents []any) bool {
	return anyStatementsMention(documents, "principal.licenses")
}

// ReconcileGroupLicenses (licenses.ts reconcileGroupLicenses): The products assigned to some groups, after their
// membership changed (teams.ts `syncTeamsFromGroups`): each product is reconciled once. Inside `batchGroupLicenses`
// the products are only noted, for the end of the batch.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReconcileGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, groupIDs any, actor any) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts reconcileGroupLicenses")
	return
}

// ReconcileIdentityLicenses (licenses.ts reconcileIdentityLicenses): Reconciles, inside the caller's transaction,
// the products that concern some identities of a tenant (their seats, direct assignments, and assignments of their
// groups), after their status or memberships changed (SCIM provisioning through
// `protocolHost.identityStatusChanged`, and `reconcileLicensesOf`). Returns the seat changes.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReconcileIdentityLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityIDs []string, actor any) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts reconcileIdentityLicenses")
	return
}

// ReconcileLicenses (licenses.ts reconcileLicenses): Brings the seats of one product (or of every product with
// assignments or seats) in a tenant in line with who claims them and the capacity of the live pools. Idempotent.
// Seats of claimants who are gone (unassigned, left the group, disabled, expired, deleted) are released; the rest
// are ranked by seniority, the first `capacity` active and the others waiting, so capacity is never over-allocated
// and a capacity cut moves the newest active seats to the waiting list. Changes are audited as
// `license:seat-activate`, `license:seat-waiting` and `license:seat-release` (resource: the identity). Callers run
// `afterIdentityChange` post-commit for the identities in the result.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReconcileLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, productID string, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts reconcileLicenses")
	return
}

// ReconcileLicensesOf (licenses.ts reconcileLicensesOf): Reconciles the products that concern some identities of a
// tenant (`reconcileIdentityLicenses`) in one transaction, after an administrator changed them
// (package-automation.ts `afterIdentityChange`). Returns the identities whose seats changed; never throws (the
// scheduled reconcile catches up).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReconcileLicensesOf(ctx context.Context, server *ServerContext, tenantID string, identityIDs []string, actor any) (result []string, err error) {
	err = notImplemented("licenses.ts reconcileLicensesOf")
	return
}

// ReleaseGroupLicenses (licenses.ts releaseGroupLicenses): When a group is deleted: its license assignments go with
// it, and the seats they carried follow.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseGroupLicenses(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, groupID string, actor any) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts releaseGroupLicenses")
	return
}

// ReleaseLicensesOf (licenses.ts releaseLicensesOf): When a person is deleted: their direct assignments go and their
// seats are released (their group memberships are already gone), and waiting people move up.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseLicensesOf(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, actor any) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts releaseLicensesOf")
	return
}

// ResolveLicenseSettings (licenses.ts resolveLicenseSettings): A tenant's settings with defaults (reclaim off, no
// waiting-list email).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveLicenseSettings(ctx context.Context, reader core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("licenses.ts resolveLicenseSettings")
	return
}

// VisibleLicenseProducts (licenses.ts visibleLicenseProducts): Every product visible to a tenant: its own and those
// of its ancestors (the root tenant's are platform products).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VisibleLicenseProducts(ctx context.Context, reader core.IamStore, tenantID string) (result []*core.Object, err error) {
	err = notImplemented("licenses.ts visibleLicenseProducts")
	return
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
