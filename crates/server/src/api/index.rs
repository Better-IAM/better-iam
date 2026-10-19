//! Port of `packages/server/src/api/index.ts`: the provisioning API. Every group is an object of `(credential, input)`
//! operations that run through the transactional authorization envelope; the HTTP router ([`crate::api::dispatch`])
//! maps `POST {basePath}/{group}/{method}` onto them.

use std::sync::Arc;

use better_iam_core::{CredentialInput, IamResult};
use better_iam_types::api::assertions;

use crate::api::{Body, Reply};
use crate::context::ServerContext;
use crate::http::AuthApi;

/// `createApi(ctx, auth)`'s result (`Api`): the authentication API and one object per API group.
pub struct Api {
    pub auth: Arc<AuthApi>,
    pub tenants: Arc<crate::api::tenants::TenantsApi>,
    pub identities: Arc<crate::api::identities::IdentitiesApi>,
    pub policies: Arc<crate::api::policies::PoliciesApi>,
    pub roles: Arc<crate::api::roles::RolesApi>,
    pub bindings: Arc<crate::api::bindings::BindingsApi>,
    pub authorities: Arc<crate::api::bindings::AuthoritiesApi>,
    pub groups: Arc<crate::api::groups::GroupsApi>,
    pub actions: Arc<crate::api::catalog::ActionsApi>,
    pub resource_types: Arc<crate::api::catalog::ResourceTypesApi>,
    pub resources: Arc<crate::api::resources::ResourcesApi>,
    pub relationships: Arc<crate::api::relationships::RelationshipsApi>,
    pub service_accounts: Arc<crate::api::service_accounts::ServiceAccountsApi>,
    pub credentials: Arc<crate::api::service_accounts::CredentialsApi>,
    pub trust: Arc<crate::api::trust::TrustApi>,
    pub links: Arc<crate::api::trust::LinksApi>,
    pub root: Arc<crate::api::trust::RootApi>,
    pub access_requests: Arc<crate::api::access_requests::AccessRequestsApi>,
    pub webhooks: Arc<crate::api::webhooks::WebhooksApi>,
    pub audit: Arc<crate::api::webhooks::AuditApi>,
    pub assertions: Arc<AssertionsGroup>,
    pub config: Arc<crate::sync::ConfigApi>,
    pub reports: Arc<crate::api::reports::ReportsApi>,
    pub packages: Arc<crate::api::packages::PackagesApi>,
    pub domains: Arc<crate::api::domains::DomainsApi>,
    pub hostnames: Arc<crate::api::hostnames::HostnamesApi>,
    pub analysis: Arc<crate::api::analysis::AnalysisApi>,
    pub certifications: Arc<crate::api::certifications::CertificationsApi>,
    pub sod: Arc<crate::api::sod::SodApi>,
    pub security: Arc<crate::api::security::SecurityApi>,
    pub role_mining: Arc<crate::api::role_mining::RoleMiningApi>,
    pub impact: Arc<crate::api::impact::ImpactApi>,
    pub invariants: Arc<crate::api::invariants::InvariantsApi>,
    pub agreements: Arc<crate::api::agreements::AgreementsApi>,
    pub access_paths: Arc<crate::api::access_paths::AccessPathsApi>,
    pub sts: Arc<crate::api::sts::StsApi>,
    pub oidc_providers: Arc<crate::api::oidc_providers::OidcProvidersApi>,
    pub features: Arc<crate::api::features::FeaturesApi>,
    pub onboarding: Arc<crate::api::onboarding::OnboardingApi>,
    pub agents: Arc<crate::api::agents::AgentsApi>,
    pub delegations: Arc<crate::api::delegations::DelegationsApi>,
    pub inference: Arc<crate::api::inference::InferenceApi>,
    pub teams: Arc<crate::api::teams::TeamsApi>,
    pub departments: Arc<crate::api::departments::DepartmentsApi>,
    pub billing: Arc<crate::api::billing::BillingApi>,
    pub keys: Arc<crate::api::keys::KeysApi>,
    pub pki: Arc<crate::api::pki::PkiApi>,
    pub protection: Arc<crate::api::protection::ProtectionApi>,
    pub vault: Arc<crate::api::vault::VaultApi>,
    pub privacy: Arc<crate::api::privacy::PrivacyApi>,
    pub workflows: Arc<crate::api::workflows::WorkflowsApi>,
    pub compliance: Arc<crate::api::compliance::ComplianceApi>,
    pub applications: Arc<crate::api::applications::ApplicationsApi>,
    pub ssh: Arc<crate::api::ssh::SshApi>,
    pub verifiable_credentials: Arc<crate::api::verifiable_credentials::VerifiableCredentialsApi>,
    pub ldap: Arc<crate::api::ldap::LdapApi>,
    pub threats: Arc<crate::api::threats::ThreatsApi>,
    pub devices: Arc<crate::api::devices::DevicesApi>,
    pub filters: Arc<crate::api::filters::FiltersApi>,
    pub quotas: Arc<crate::api::quotas::QuotasApi>,
    pub signals: Arc<crate::api::signals::SignalsApi>,
    pub licenses: Arc<crate::api::licenses::LicensesApi>,
    pub guests: Arc<crate::api::guests::GuestsApi>,
    pub clearances: Arc<crate::api::clearances::ClearancesApi>,
}

/// `createApi(ctx, auth)`.
pub fn create_api(ctx: &Arc<ServerContext>, auth: Arc<AuthApi>) -> IamResult<Api> {
    Ok(Api {
        auth,
        tenants: Arc::new(crate::api::tenants::create_tenants_api(ctx)?),
        identities: Arc::new(crate::api::identities::create_identities_api(ctx)?),
        policies: Arc::new(crate::api::policies::create_policies_api(ctx)?),
        roles: Arc::new(crate::api::roles::create_roles_api(ctx)?),
        bindings: Arc::new(crate::api::bindings::create_bindings_api(ctx)?),
        authorities: Arc::new(crate::api::bindings::create_authorities_api(ctx)?),
        groups: Arc::new(crate::api::groups::create_groups_api(ctx)?),
        actions: Arc::new(crate::api::catalog::create_actions_api(ctx)?),
        resource_types: Arc::new(crate::api::catalog::create_resource_types_api(ctx)?),
        resources: Arc::new(crate::api::resources::create_resources_api(ctx)?),
        relationships: Arc::new(crate::api::relationships::create_relationships_api(ctx)?),
        service_accounts: Arc::new(crate::api::service_accounts::create_service_accounts_api(
            ctx,
        )?),
        credentials: Arc::new(crate::api::service_accounts::create_credentials_api(ctx)?),
        trust: Arc::new(crate::api::trust::create_trust_api(ctx)?),
        links: Arc::new(crate::api::trust::create_links_api(ctx)?),
        root: Arc::new(crate::api::trust::create_root_api(ctx)?),
        access_requests: Arc::new(crate::api::access_requests::create_access_requests_api(
            ctx,
        )?),
        webhooks: Arc::new(crate::api::webhooks::create_webhooks_api(ctx)?),
        audit: Arc::new(crate::api::webhooks::create_audit_api(ctx)?),
        assertions: Arc::new(AssertionsGroup {
            inner: crate::assertions::create_assertions_api(ctx.clone()),
        }),
        config: Arc::new(crate::sync::create_config_api(ctx)?),
        reports: Arc::new(crate::api::reports::create_reports_api(ctx)?),
        packages: Arc::new(crate::api::packages::create_packages_api(ctx)?),
        domains: Arc::new(crate::api::domains::create_domains_api(ctx)?),
        hostnames: Arc::new(crate::api::hostnames::create_hostnames_api(ctx)?),
        analysis: Arc::new(crate::api::analysis::create_analysis_api(ctx)?),
        certifications: Arc::new(crate::api::certifications::create_certifications_api(ctx)?),
        sod: Arc::new(crate::api::sod::create_sod_api(ctx)?),
        security: Arc::new(crate::api::security::create_security_api(ctx)?),
        role_mining: Arc::new(crate::api::role_mining::create_role_mining_api(ctx)?),
        impact: Arc::new(crate::api::impact::create_impact_api(ctx)?),
        invariants: Arc::new(crate::api::invariants::create_invariants_api(ctx)?),
        agreements: Arc::new(crate::api::agreements::create_agreements_api(ctx)?),
        access_paths: Arc::new(crate::api::access_paths::create_access_paths_api(ctx)?),
        sts: Arc::new(crate::api::sts::create_sts_api(ctx)?),
        oidc_providers: Arc::new(crate::api::oidc_providers::create_oidc_providers_api(ctx)?),
        features: Arc::new(crate::api::features::create_features_api(ctx)?),
        onboarding: Arc::new(crate::api::onboarding::create_onboarding_api(ctx)?),
        agents: Arc::new(crate::api::agents::create_agents_api(ctx)?),
        delegations: Arc::new(crate::api::delegations::create_delegations_api(ctx)?),
        inference: Arc::new(crate::api::inference::create_inference_api(ctx)?),
        teams: Arc::new(crate::api::teams::create_teams_api(ctx)?),
        departments: Arc::new(crate::api::departments::create_departments_api(ctx)?),
        billing: Arc::new(crate::api::billing::create_billing_api(ctx)?),
        keys: Arc::new(crate::api::keys::create_keys_api(ctx)?),
        pki: Arc::new(crate::api::pki::create_pki_api(ctx)?),
        protection: Arc::new(crate::api::protection::create_protection_api(ctx)?),
        vault: Arc::new(crate::api::vault::create_vault_api(ctx)?),
        privacy: Arc::new(crate::api::privacy::create_privacy_api(ctx)?),
        workflows: Arc::new(crate::api::workflows::create_workflows_api(ctx)?),
        compliance: Arc::new(crate::api::compliance::create_compliance_api(ctx)?),
        applications: Arc::new(crate::api::applications::create_applications_api(ctx)?),
        ssh: Arc::new(crate::api::ssh::create_ssh_api(ctx)?),
        verifiable_credentials: Arc::new(
            crate::api::verifiable_credentials::create_verifiable_credentials_api(ctx)?,
        ),
        ldap: Arc::new(crate::api::ldap::create_ldap_api(ctx)?),
        threats: Arc::new(crate::api::threats::create_threats_api(ctx)?),
        devices: Arc::new(crate::api::devices::create_devices_api(ctx)?),
        filters: Arc::new(crate::api::filters::create_filters_api(ctx)?),
        quotas: Arc::new(crate::api::quotas::create_quotas_api(ctx)?),
        signals: Arc::new(crate::api::signals::create_signals_api(ctx)?),
        licenses: Arc::new(crate::api::licenses::create_licenses_api(ctx)?),
        guests: Arc::new(crate::api::guests::create_guests_api(ctx)?),
        clearances: Arc::new(crate::api::clearances::create_clearances_api(ctx)?),
    })
}

/// The `assertions` group: `createAssertionsApi(ctx)` of assertions.ts, typed for the route table.
pub struct AssertionsGroup {
    inner: crate::assertions::AssertionsApi,
}

impl AssertionsGroup {
    /// `assertions/issue`.
    pub async fn issue(
        &self,
        credential: &CredentialInput,
        input: Body<assertions::IssueInput>,
    ) -> IamResult<Reply<assertions::IssueOutput>> {
        Ok(Reply::json(
            self.inner.issue(credential, &input.value()).await?,
        ))
    }
}
