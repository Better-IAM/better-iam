package server

// Skeleton of packages/server/src/api/licenses.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// AddPool is POST {basePath}/licenses/addPool. Gives a tenant seats of a product: a quantity, optionally from a start until an end.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) AddPool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAddPoolInput]) (Out[apitypes.LicensesAddPoolOutput], error) {
	return Out[apitypes.LicensesAddPoolOutput]{}, notImplemented("licenses.addPool")
}

// Assign is POST {basePath}/licenses/assign. Gives a product to a person or a group of the tenant; the person, or each live member of the group, claims a seat.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAssignInput]) (Out[apitypes.LicensesAssignOutput], error) {
	return Out[apitypes.LicensesAssignOutput]{}, notImplemented("licenses.assign")
}

// AssignMany is POST {basePath}/licenses/assignMany. Gives a product to up to 100 people in one transaction.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) AssignMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesAssignManyInput]) (Out[apitypes.LicensesAssignManyOutput], error) {
	return Out[apitypes.LicensesAssignManyOutput]{}, notImplemented("licenses.assignMany")
}

// Configure is POST {basePath}/licenses/configure. Turns inactive-seat reclaim and waiting-list email on or off for the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesConfigureInput]) (Out[apitypes.LicensesConfigureOutput], error) {
	return Out[apitypes.LicensesConfigureOutput]{}, notImplemented("licenses.configure")
}

// CreateProduct is POST {basePath}/licenses/createProduct. Defines a product: a permanent key, a name, and the feature keys a seat unlocks.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) CreateProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesCreateProductInput]) (Out[apitypes.LicensesCreateProductOutput], error) {
	return Out[apitypes.LicensesCreateProductOutput]{}, notImplemented("licenses.createProduct")
}

// GetProduct is POST {basePath}/licenses/getProduct. Returns one product visible to the tenant, with where it is defined and whether it is shadowed.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) GetProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesGetProductInput]) (Out[apitypes.LicensesGetProductOutput], error) {
	return Out[apitypes.LicensesGetProductOutput]{}, notImplemented("licenses.getProduct")
}

// GetSettings is POST {basePath}/licenses/getSettings. Returns the tenant's license settings, with the defaults when they were never configured.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesGetSettingsInput]) (Out[apitypes.LicensesGetSettingsOutput], error) {
	return Out[apitypes.LicensesGetSettingsOutput]{}, notImplemented("licenses.getSettings")
}

// ListAssignments is POST {basePath}/licenses/listAssignments. Lists the tenant's assignments, newest first, optionally of one product or subject.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListAssignmentsInput]) (Out[apitypes.LicensesListAssignmentsOutput], error) {
	return Out[apitypes.LicensesListAssignmentsOutput]{}, notImplemented("licenses.listAssignments")
}

// ListPools is POST {basePath}/licenses/listPools. Lists the tenant's pools and, for products it defines, the pools it granted to tenants below it, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) ListPools(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListPoolsInput]) (Out[apitypes.LicensesListPoolsOutput], error) {
	return Out[apitypes.LicensesListPoolsOutput]{}, notImplemented("licenses.listPools")
}

// ListProducts is POST {basePath}/licenses/listProducts. Lists the products the tenant can use, its own and its ancestors', sorted by key.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) ListProducts(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListProductsInput]) (Out[apitypes.LicensesListProductsOutput], error) {
	return Out[apitypes.LicensesListProductsOutput]{}, notImplemented("licenses.listProducts")
}

// ListSeats is POST {basePath}/licenses/listSeats. Lists the tenant's seats: who holds each product and who waits, in order.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) ListSeats(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesListSeatsInput]) (Out[apitypes.LicensesListSeatsOutput], error) {
	return Out[apitypes.LicensesListSeatsOutput]{}, notImplemented("licenses.listSeats")
}

// Mine is POST {basePath}/licenses/mine. Returns the caller's own licenses in the tenant, waiting-list places included, and the feature keys they unlock.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesMineInput]) (Out[apitypes.LicensesMineOutput], error) {
	return Out[apitypes.LicensesMineOutput]{}, notImplemented("licenses.mine")
}

// RemovePool is POST {basePath}/licenses/removePool. Removes a pool; the newest active seats beyond the remaining capacity move to the waiting list.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) RemovePool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesRemovePoolInput]) (Out[apitypes.LicensesRemovePoolOutput], error) {
	return Out[apitypes.LicensesRemovePoolOutput]{}, notImplemented("licenses.removePool")
}

// RetireProduct is POST {basePath}/licenses/retireProduct. Retires a product for good, releasing its seats in every tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) RetireProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesRetireProductInput]) (Out[apitypes.LicensesRetireProductOutput], error) {
	return Out[apitypes.LicensesRetireProductOutput]{}, notImplemented("licenses.retireProduct")
}

// Unassign is POST {basePath}/licenses/unassign. Removes an assignment; seats it carried are released unless another assignment still covers the person.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUnassignInput]) (Out[apitypes.LicensesUnassignOutput], error) {
	return Out[apitypes.LicensesUnassignOutput]{}, notImplemented("licenses.unassign")
}

// UpdatePool is POST {basePath}/licenses/updatePool. Changes a pool's quantity, its end, or its note; seats follow the new capacity at once.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) UpdatePool(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUpdatePoolInput]) (Out[apitypes.LicensesUpdatePoolOutput], error) {
	return Out[apitypes.LicensesUpdatePoolOutput]{}, notImplemented("licenses.updatePool")
}

// UpdateProduct is POST {basePath}/licenses/updateProduct. Renames a product, changes its description, or replaces its feature keys; the key never changes.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) UpdateProduct(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUpdateProductInput]) (Out[apitypes.LicensesUpdateProductOutput], error) {
	return Out[apitypes.LicensesUpdateProductOutput]{}, notImplemented("licenses.updateProduct")
}

// Usage is POST {basePath}/licenses/usage. Reports, per product the tenant uses, its capacity and how many seats are active, waiting, available, and reclaimable.
//
// STUB: returns NOT_IMPLEMENTED until api/licenses.ts is ported.
func (api *LicensesAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.LicensesUsageInput]) (Out[apitypes.LicensesUsageOutput], error) {
	return Out[apitypes.LicensesUsageOutput]{}, notImplemented("licenses.usage")
}

// IamLicenses is api/licenses.ts IamLicenses.
type IamLicenses struct {
	server *ServerContext
}

// Features (api/licenses.ts IamLicenses.features): The feature keys of the products a person holds an active seat
// for in the tenant (none for inactive people), from the products the trusted tenant or one of its ancestors defines
// only. Any tenant can define a product of its own that lists any feature key, so by default only **platform**
// products (the root tenant's) count: pass `trustedTenantId` to count the products a tenant (and the tenants above
// it) sells too, such as the tenant's own.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamLicenses) Features(ctx context.Context, identityID string, tenantID string, options *core.Object) (result []string, err error) {
	err = notImplemented("api/licenses.ts IamLicenses.features")
	return
}

// Products (api/licenses.ts IamLicenses.products): The keys of the products a person holds an active seat for in the
// tenant: what `principal.licenses` holds.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamLicenses) Products(ctx context.Context, identityID string, tenantID string) (result []string, err error) {
	err = notImplemented("api/licenses.ts IamLicenses.products")
	return
}

// Reconcile (api/licenses.ts IamLicenses.reconcile): A scheduler job (hourly): brings every tenant's seats in line
// with assignments, memberships, identity status and pool terms, and re-evaluates birthright package rules for the
// people whose seats changed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamLicenses) Reconcile(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/licenses.ts IamLicenses.reconcile")
	return
}

// Reclaim (api/licenses.ts IamLicenses.reclaim): A scheduler job (daily): in tenants with `reclaimAfterDays`,
// removes direct assignments of people with no sign-in or credential use for that long (audited `license:reclaim`),
// then reconciles.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamLicenses) Reclaim(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/licenses.ts IamLicenses.reclaim")
	return
}

// CreateLicensesRuntime builds the IamLicenses (api/licenses.ts createLicensesRuntime). Its methods are stubs until the module is ported.
func CreateLicensesRuntime(server *ServerContext) *IamLicenses {
	return &IamLicenses{server: server}
}
