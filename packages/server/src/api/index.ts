import { createAssertionsApi } from '../assertions.js';
import type { ServerContext } from '../context.js';
import type { AuthApi } from '../http.js';
import { createConfigApi } from '../sync.js';
import { createAccessRequestsApi } from './access-requests.js';
import { createAnalysisApi } from './analysis.js';
import { createAuthoritiesApi, createBindingsApi } from './bindings.js';
import { createActionsApi, createResourceTypesApi } from './catalog.js';
import { createCertificationsApi } from './certifications.js';
import { createDomainsApi } from './domains.js';
import { createHostnamesApi } from './hostnames.js';
import { createGroupsApi } from './groups.js';
import { createIdentitiesApi } from './identities.js';
import { createPackagesApi } from './packages.js';
import { createPoliciesApi } from './policies.js';
import { createRelationshipsApi } from './relationships.js';
import { createReportsApi } from './reports.js';
import { createResourcesApi } from './resources.js';
import { createRoleMiningApi } from './role-mining.js';
import { createImpactApi } from './impact.js';
import { createInvariantsApi } from './invariants.js';
import { createAgreementsApi } from './agreements.js';
import { createAccessPathsApi } from './access-paths.js';
import { createRolesApi } from './roles.js';
import { createSecurityApi } from './security.js';
import { createSodApi } from './sod.js';
import { createCredentialsApi, createServiceAccountsApi } from './service-accounts.js';
import { createTenantsApi } from './tenants.js';
import { createLinksApi, createRootApi, createTrustApi } from './trust.js';
import { createAuditApi, createWebhooksApi } from './webhooks.js';
import { createStsApi } from './sts.js';
import { createOidcProvidersApi } from './oidc-providers.js';
import { createFeaturesApi } from './features.js';
import { createOnboardingApi } from './onboarding.js';
import { createAgentsApi } from './agents.js';
import { createDelegationsApi } from './delegations.js';
import { createInferenceApi } from './inference.js';
import { createTeamsApi } from './teams.js';
import { createDepartmentsApi } from './departments.js';
import { createBillingApi } from './billing.js';
import { createKeysApi } from './keys.js';
import { createPkiApi } from './pki.js';
import { createProtectionApi } from './protection.js';
import { createVaultApi } from './vault.js';
import { createPrivacyApi } from './privacy.js';
import { createWorkflowsApi } from './workflows.js';
import { createComplianceApi } from './compliance.js';
import { createApplicationsApi } from './applications.js';
import { createSshApi } from './ssh.js';
import { createVerifiableCredentialsApi } from './verifiable-credentials.js';
import { createLdapApi } from './ldap.js';
import { createThreatsApi } from './threats.js';
import { createDevicesApi } from './devices.js';
import { createFiltersApi } from './filters.js';
import { createQuotasApi } from './quotas.js';
import { createSignalsApi } from './signals.js';

/**
 * The provisioning API. Every group is an object of `(credential, input)` operations that run through the
 * transactional authorization envelope; the HTTP router maps `POST {basePath}/{group}/{method}` onto them.
 */
export function createApi(ctx: ServerContext, auth: AuthApi) {
  return {
    auth,
    tenants: createTenantsApi(ctx),
    identities: createIdentitiesApi(ctx),
    policies: createPoliciesApi(ctx),
    roles: createRolesApi(ctx),
    bindings: createBindingsApi(ctx),
    authorities: createAuthoritiesApi(ctx),
    groups: createGroupsApi(ctx),
    actions: createActionsApi(ctx),
    resourceTypes: createResourceTypesApi(ctx),
    resources: createResourcesApi(ctx),
    relationships: createRelationshipsApi(ctx),
    serviceAccounts: createServiceAccountsApi(ctx),
    credentials: createCredentialsApi(ctx),
    trust: createTrustApi(ctx),
    links: createLinksApi(ctx),
    root: createRootApi(ctx),
    accessRequests: createAccessRequestsApi(ctx),
    webhooks: createWebhooksApi(ctx),
    audit: createAuditApi(ctx),
    assertions: createAssertionsApi(ctx),
    config: createConfigApi(ctx),
    reports: createReportsApi(ctx),
    packages: createPackagesApi(ctx),
    domains: createDomainsApi(ctx),
    hostnames: createHostnamesApi(ctx),
    analysis: createAnalysisApi(ctx),
    certifications: createCertificationsApi(ctx),
    sod: createSodApi(ctx),
    security: createSecurityApi(ctx),
    roleMining: createRoleMiningApi(ctx),
    impact: createImpactApi(ctx),
    invariants: createInvariantsApi(ctx),
    agreements: createAgreementsApi(ctx),
    accessPaths: createAccessPathsApi(ctx),
    sts: createStsApi(ctx),
    oidcProviders: createOidcProvidersApi(ctx),
    features: createFeaturesApi(ctx),
    onboarding: createOnboardingApi(ctx),
    agents: createAgentsApi(ctx),
    delegations: createDelegationsApi(ctx),
    inference: createInferenceApi(ctx),
    teams: createTeamsApi(ctx),
    departments: createDepartmentsApi(ctx),
    billing: createBillingApi(ctx),
    keys: createKeysApi(ctx),
    pki: createPkiApi(ctx),
    protection: createProtectionApi(ctx),
    vault: createVaultApi(ctx),
    privacy: createPrivacyApi(ctx),
    workflows: createWorkflowsApi(ctx),
    compliance: createComplianceApi(ctx),
    applications: createApplicationsApi(ctx),
    ssh: createSshApi(ctx),
    verifiableCredentials: createVerifiableCredentialsApi(ctx),
    ldap: createLdapApi(ctx),
    threats: createThreatsApi(ctx),
    devices: createDevicesApi(ctx),
    filters: createFiltersApi(ctx),
    quotas: createQuotasApi(ctx),
    signals: createSignalsApi(ctx),
  };
}
export type Api = ReturnType<typeof createApi>;
