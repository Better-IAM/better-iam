package server

// Skeleton of packages/server/src/api/threats.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// AddNote is POST {basePath}/threats/addNote. Adds an investigation note to an incident.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) AddNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsAddNoteInput]) (Out[apitypes.ThreatsAddNoteOutput], error) {
	return Out[apitypes.ThreatsAddNoteOutput]{}, notImplemented("threats.addNote")
}

// Configure is POST {basePath}/threats/configure. Tunes detection for the tenant: rules, trusted networks, dormancy, risk decay, alert recipients, and the containment brake.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsConfigureInput]) (Out[apitypes.ThreatsConfigureOutput], error) {
	return Out[apitypes.ThreatsConfigureOutput]{}, notImplemented("threats.configure")
}

// CreatePlaybook is POST {basePath}/threats/createPlaybook. Defines an automatic response: actions that run when a new detection matches the trigger.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) CreatePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsCreatePlaybookInput]) (Out[apitypes.ThreatsCreatePlaybookOutput], error) {
	return Out[apitypes.ThreatsCreatePlaybookOutput]{}, notImplemented("threats.createPlaybook")
}

// DeletePlaybook is POST {basePath}/threats/deletePlaybook. Deletes a playbook; responses it already took stay on their incidents.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) DeletePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDeletePlaybookInput]) (Out[apitypes.ThreatsDeletePlaybookOutput], error) {
	return Out[apitypes.ThreatsDeletePlaybookOutput]{}, notImplemented("threats.deletePlaybook")
}

// Detect is POST {basePath}/threats/detect. Runs detection for the tenant now instead of waiting for the scheduled job, and returns what the run did.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Detect(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDetectInput]) (Out[apitypes.ThreatsDetectOutput], error) {
	return Out[apitypes.ThreatsDetectOutput]{}, notImplemented("threats.detect")
}

// DismissDetection is POST {basePath}/threats/dismissDetection. Marks an open detection as a false alarm and takes its points out of the identity's risk.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) DismissDetection(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDismissDetectionInput]) (Out[apitypes.ThreatsDismissDetectionOutput], error) {
	return Out[apitypes.ThreatsDismissDetectionOutput]{}, notImplemented("threats.dismissDetection")
}

// GetDetection is POST {basePath}/threats/getDetection. Returns one detection with its evidence.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) GetDetection(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetDetectionInput]) (Out[apitypes.ThreatsGetDetectionOutput], error) {
	return Out[apitypes.ThreatsGetDetectionOutput]{}, notImplemented("threats.getDetection")
}

// GetIncident is POST {basePath}/threats/getIncident. Returns an incident with its detections, notes, responses, and the risk of the identity it concerns.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) GetIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetIncidentInput]) (Out[apitypes.ThreatsGetIncidentOutput], error) {
	return Out[apitypes.ThreatsGetIncidentOutput]{}, notImplemented("threats.getIncident")
}

// GetRisk is POST {basePath}/threats/getRisk. Returns one identity's risk: score, level, override, containment, and the contributions behind them.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) GetRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetRiskInput]) (Out[apitypes.ThreatsGetRiskOutput], error) {
	return Out[apitypes.ThreatsGetRiskOutput]{}, notImplemented("threats.getRisk")
}

// GetSettings is POST {basePath}/threats/getSettings. Returns the tenant's detection settings with every default applied.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetSettingsInput]) (Out[apitypes.ThreatsGetSettingsOutput], error) {
	return Out[apitypes.ThreatsGetSettingsOutput]{}, notImplemented("threats.getSettings")
}

// ListDetections is POST {basePath}/threats/listDetections. Lists the tenant's detections, newest first, optionally narrowed by status, rule, severity, identity, incident, and time.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ListDetections(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListDetectionsInput]) (Out[apitypes.ThreatsListDetectionsOutput], error) {
	return Out[apitypes.ThreatsListDetectionsOutput]{}, notImplemented("threats.listDetections")
}

// ListIncidents is POST {basePath}/threats/listIncidents. Lists the tenant's incidents, most recently active first, optionally narrowed by status, severity, assignee, and identity.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ListIncidents(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListIncidentsInput]) (Out[apitypes.ThreatsListIncidentsOutput], error) {
	return Out[apitypes.ThreatsListIncidentsOutput]{}, notImplemented("threats.listIncidents")
}

// ListPlaybooks is POST {basePath}/threats/listPlaybooks. Lists the tenant's playbooks by name.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ListPlaybooks(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListPlaybooksInput]) (Out[apitypes.ThreatsListPlaybooksOutput], error) {
	return Out[apitypes.ThreatsListPlaybooksOutput]{}, notImplemented("threats.listPlaybooks")
}

// ListRisk is POST {basePath}/threats/listRisk. Lists the identities at or above a risk level, and contained ones, highest score first.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ListRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListRiskInput]) (Out[apitypes.ThreatsListRiskOutput], error) {
	return Out[apitypes.ThreatsListRiskOutput]{}, notImplemented("threats.listRisk")
}

// Release is POST {basePath}/threats/release. Lifts a containment, so the identity is active again and its API keys work.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Release(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsReleaseInput]) (Out[apitypes.ThreatsReleaseOutput], error) {
	return Out[apitypes.ThreatsReleaseOutput]{}, notImplemented("threats.release")
}

// ReportSuspicious is POST {basePath}/threats/reportSuspicious. Lets a person report activity on their own account that was not them: it raises an incident and signs out everywhere else.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ReportSuspicious(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsReportSuspiciousInput]) (Out[apitypes.ThreatsReportSuspiciousOutput], error) {
	return Out[apitypes.ThreatsReportSuspiciousOutput]{}, notImplemented("threats.reportSuspicious")
}

// ResolveIncident is POST {basePath}/threats/resolveIncident. Closes an incident as a true positive, a false positive, or benign.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) ResolveIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsResolveIncidentInput]) (Out[apitypes.ThreatsResolveIncidentOutput], error) {
	return Out[apitypes.ThreatsResolveIncidentOutput]{}, notImplemented("threats.resolveIncident")
}

// Respond is POST {basePath}/threats/respond. Responds by hand to an incident, an identity, or a network with one to five response actions.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Respond(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsRespondInput]) (Out[apitypes.ThreatsRespondOutput], error) {
	return Out[apitypes.ThreatsRespondOutput]{}, notImplemented("threats.respond")
}

// Rules is POST {basePath}/threats/rules. Lists every detection rule with its defaults, tuning bounds, and the setting in force for the tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Rules(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsRulesInput]) (Out[apitypes.ThreatsRulesOutput], error) {
	return Out[apitypes.ThreatsRulesOutput]{}, notImplemented("threats.rules")
}

// SetRisk is POST {basePath}/threats/setRisk. Sets an identity's risk level by hand, as a floor that holds until it expires, or clears it.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) SetRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsSetRiskInput]) (Out[apitypes.ThreatsSetRiskOutput], error) {
	return Out[apitypes.ThreatsSetRiskOutput]{}, notImplemented("threats.setRisk")
}

// Summary is POST {basePath}/threats/summary. Returns the tenant's threat posture at a glance for a dashboard.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Summary(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsSummaryInput]) (Out[apitypes.ThreatsSummaryOutput], error) {
	return Out[apitypes.ThreatsSummaryOutput]{}, notImplemented("threats.summary")
}

// Timeline is POST {basePath}/threats/timeline. Returns an identity's recent audit trail, newest first: what it did and what was done to it.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) Timeline(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsTimelineInput]) (Out[apitypes.ThreatsTimelineOutput], error) {
	return Out[apitypes.ThreatsTimelineOutput]{}, notImplemented("threats.timeline")
}

// UpdateIncident is POST {basePath}/threats/updateIncident. Moves an incident between open and investigating, assigns it, or changes its severity.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) UpdateIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsUpdateIncidentInput]) (Out[apitypes.ThreatsUpdateIncidentOutput], error) {
	return Out[apitypes.ThreatsUpdateIncidentOutput]{}, notImplemented("threats.updateIncident")
}

// UpdatePlaybook is POST {basePath}/threats/updatePlaybook. Changes a playbook's name, description, trigger, actions, or whether it is enabled.
//
// STUB: returns NOT_IMPLEMENTED until api/threats.ts is ported.
func (api *ThreatsAPI) UpdatePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsUpdatePlaybookInput]) (Out[apitypes.ThreatsUpdatePlaybookOutput], error) {
	return Out[apitypes.ThreatsUpdatePlaybookOutput]{}, notImplemented("threats.updatePlaybook")
}
