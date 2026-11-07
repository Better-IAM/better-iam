package server

// Skeleton of packages/server/src/api/devices.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// DevicesAPI is the `devices` API group (packages/server/src/api/devices.ts createDevicesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/devices/{method} onto it.
type DevicesAPI struct {
	server *ServerContext
}

// CreateDevicesAPI builds the `devices` API group.
func CreateDevicesAPI(server *ServerContext) *DevicesAPI {
	return &DevicesAPI{server: server}
}

// Check is POST {basePath}/devices/check. Reports what the device presenting this request proves: its assurance, id, platform and compliance.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCheckInput]) (Out[apitypes.DevicesCheckOutput], error) {
	return Out[apitypes.DevicesCheckOutput]{}, notImplemented("devices.check")
}

// Configure is POST {basePath}/devices/configure. Sets the requirements a managed device must meet to be compliant.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesConfigureInput]) (Out[apitypes.DevicesConfigureOutput], error) {
	return Out[apitypes.DevicesConfigureOutput]{}, notImplemented("devices.configure")
}

// CreateEnrollment is POST {basePath}/devices/createEnrollment. Creates a one-time enrollment code that binds a browser or agent key to a device, usually one an integration manages.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) CreateEnrollment(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCreateEnrollmentInput]) (Out[apitypes.DevicesCreateEnrollmentOutput], error) {
	return Out[apitypes.DevicesCreateEnrollmentOutput]{}, notImplemented("devices.createEnrollment")
}

// CreateIntegration is POST {basePath}/devices/createIntegration. Adds an MDM or EDR integration that can report devices and their posture.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) CreateIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCreateIntegrationInput]) (Out[apitypes.DevicesCreateIntegrationOutput], error) {
	return Out[apitypes.DevicesCreateIntegrationOutput]{}, notImplemented("devices.createIntegration")
}

// Delete is POST {basePath}/devices/delete. Deletes a device with its keys and enrollment codes.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesDeleteInput]) (Out[apitypes.DevicesDeleteOutput], error) {
	return Out[apitypes.DevicesDeleteOutput]{}, notImplemented("devices.delete")
}

// DeleteIntegration is POST {basePath}/devices/deleteIntegration. Deletes an integration, optionally leaving the devices it manages unmanaged.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) DeleteIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesDeleteIntegrationInput]) (Out[apitypes.DevicesDeleteIntegrationOutput], error) {
	return Out[apitypes.DevicesDeleteIntegrationOutput]{}, notImplemented("devices.deleteIntegration")
}

// Enroll is POST {basePath}/devices/enroll. Enrolls a public key for the caller's browser or agent, creating their device or binding the key to a device with an enrollment code.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Enroll(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesEnrollInput]) (Out[apitypes.DevicesEnrollOutput], error) {
	return Out[apitypes.DevicesEnrollOutput]{}, notImplemented("devices.enroll")
}

// Get is POST {basePath}/devices/get. Returns one device with its enrolled keys.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesGetInput]) (Out[apitypes.DevicesGetOutput], error) {
	return Out[apitypes.DevicesGetOutput]{}, notImplemented("devices.get")
}

// GetSettings is POST {basePath}/devices/getSettings. Returns the tenant's compliance requirements, or the defaults until they are configured.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesGetSettingsInput]) (Out[apitypes.DevicesGetSettingsOutput], error) {
	return Out[apitypes.DevicesGetSettingsOutput]{}, notImplemented("devices.getSettings")
}

// List is POST {basePath}/devices/list. Lists the tenant's devices, newest first, each with its compliance, assurance, key count and owner.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListInput]) (Out[apitypes.DevicesListOutput], error) {
	return Out[apitypes.DevicesListOutput]{}, notImplemented("devices.list")
}

// ListEnrollments is POST {basePath}/devices/listEnrollments. Lists the tenant's enrollment codes, newest first, without the codes themselves.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) ListEnrollments(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListEnrollmentsInput]) (Out[apitypes.DevicesListEnrollmentsOutput], error) {
	return Out[apitypes.DevicesListEnrollmentsOutput]{}, notImplemented("devices.listEnrollments")
}

// ListIntegrations is POST {basePath}/devices/listIntegrations. Lists the tenant's MDM and EDR integrations by name, with the number of devices each manages.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) ListIntegrations(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListIntegrationsInput]) (Out[apitypes.DevicesListIntegrationsOutput], error) {
	return Out[apitypes.DevicesListIntegrationsOutput]{}, notImplemented("devices.listIntegrations")
}

// Mine is POST {basePath}/devices/mine. Lists the caller's devices that are not retired, each with its compliance and assurance, the device presenting this request first.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesMineInput]) (Out[apitypes.DevicesMineOutput], error) {
	return Out[apitypes.DevicesMineOutput]{}, notImplemented("devices.mine")
}

// RemoveKey is POST {basePath}/devices/removeKey. Removes one enrolled key from a device, such as a lost browser profile or a replaced agent.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) RemoveKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRemoveKeyInput]) (Out[apitypes.DevicesRemoveKeyOutput], error) {
	return Out[apitypes.DevicesRemoveKeyOutput]{}, notImplemented("devices.removeKey")
}

// Report is POST {basePath}/devices/report. Creates or updates up to 500 devices with their posture, as reported by an integration, all or nothing.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Report(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesReportInput]) (Out[apitypes.DevicesReportOutput], error) {
	return Out[apitypes.DevicesReportOutput]{}, notImplemented("devices.report")
}

// Retire is POST {basePath}/devices/retire. Retires a device for good, deleting its keys and pending enrollment codes.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Retire(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRetireInput]) (Out[apitypes.DevicesRetireOutput], error) {
	return Out[apitypes.DevicesRetireOutput]{}, notImplemented("devices.retire")
}

// RetireMine is POST {basePath}/devices/retireMine. Retires one of the caller's own unmanaged devices and deletes its keys.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) RetireMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRetireMineInput]) (Out[apitypes.DevicesRetireMineOutput], error) {
	return Out[apitypes.DevicesRetireMineOutput]{}, notImplemented("devices.retireMine")
}

// RevokeEnrollment is POST {basePath}/devices/revokeEnrollment. Withdraws an enrollment code, used or not.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) RevokeEnrollment(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRevokeEnrollmentInput]) (Out[apitypes.DevicesRevokeEnrollmentOutput], error) {
	return Out[apitypes.DevicesRevokeEnrollmentOutput]{}, notImplemented("devices.revokeEnrollment")
}

// Update is POST {basePath}/devices/update. Renames a device, changes its owner, or marks it lost or active again.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesUpdateInput]) (Out[apitypes.DevicesUpdateOutput], error) {
	return Out[apitypes.DevicesUpdateOutput]{}, notImplemented("devices.update")
}

// UpdateIntegration is POST {basePath}/devices/updateIntegration. Renames an integration, disables or enables it, or changes whether the vendor's verdict counts.
//
// STUB: returns NOT_IMPLEMENTED until api/devices.ts is ported.
func (api *DevicesAPI) UpdateIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesUpdateIntegrationInput]) (Out[apitypes.DevicesUpdateIntegrationOutput], error) {
	return Out[apitypes.DevicesUpdateIntegrationOutput]{}, notImplemented("devices.updateIntegration")
}
