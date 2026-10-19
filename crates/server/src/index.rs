//! Port of `packages/server/src/index.ts`: the composition root ([`better_iam`], `betterIam(options)`): configuration
//! and catalog validation, the authentication service, the shared context, the service modules, the provisioning API,
//! deployment helpers, federation callbacks, and the HTTP transports. The TypeScript re-exports are the crate's
//! modules; this file holds only the composition.

use std::sync::{Arc, OnceLock, Weak};

use better_iam_auth::{AuthOptions, AuthService, DeliveryError, DeliveryMessage, create_auth};
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Decision, IamError, IamPlugin, IamResult, IamStore,
    IamStoreExt, Identity, IdentityStatus, Session,
};
use futures::future::BoxFuture;
use serde_json::{Value, json};

use crate::a2a::{A2aRuntime, create_a2a_runtime};
use crate::api::applications::{ApplicationsRuntime, create_applications_runtime};
use crate::api::billing::{BillingRuntime, create_billing_runtime};
use crate::api::clearances::{ClearancesRuntime, create_clearances_runtime};
use crate::api::compliance::{ComplianceRuntime, create_compliance_runtime};
use crate::api::features::{FeatureEvaluator, create_feature_evaluator};
use crate::api::filters::{PlanRuntime, create_plan_runtime};
use crate::api::guests::{GuestsRuntime, create_guests_runtime};
use crate::api::index::{Api, create_api};
use crate::api::inference::{InferenceRuntime, create_inference_runtime};
use crate::api::keys::{KmsRuntime, create_kms_runtime};
use crate::api::licenses::{LicensesRuntime, create_licenses_runtime};
use crate::api::pki::{PkiRuntime, create_pki_runtime};
use crate::api::privacy::{PrivacyRuntime, create_privacy_runtime};
use crate::api::protection::{ProtectionRuntime, create_protection_runtime};
use crate::api::quotas::{QuotasRuntime, create_quotas_runtime};
use crate::api::ssh::{SshRuntime, create_ssh_runtime};
use crate::api::vault::{VaultRuntime, create_vault_runtime};
use crate::api::verifiable_credentials::{VcRuntime, create_vc_protocol, create_vc_runtime};
use crate::api::workflows::{WorkflowsRuntime, create_workflows_runtime};
use crate::assertions::assertion_key;
use crate::audit_archive::{AuditArchive, create_audit_archive};
use crate::catalog::Catalog;
use crate::certification_worker::{CertificationWorker, create_certification_worker};
use crate::client_info::client_from_headers;
use crate::context::{ContextBase, NowFn, ServerContext, create_context};
use crate::contracts::{AccessibleResources, BatchResult, SessionTokenSigner};
use crate::decisions::create_decisions;
use crate::events::create_events;
use crate::federation::{Federation, create_federation};
use crate::flows::create_flows;
use crate::hosts::{HostMatch, create_hosts};
use crate::http::{AuthApi, ClientOf, Http, HttpExtras, create_auth_api, create_http};
use crate::inference::inference_plugins;
use crate::ldap::{LdapRuntime, create_ldap_runtime};
use crate::lifecycle::{Lifecycle, create_lifecycle};
use crate::metrics::{MetricsCollector, MetricsOptions, create_metrics};
use crate::observe::{IamSpan, create_observer};
use crate::operations::create_operations;
use crate::options::{
    AccessibleResourcesRequest, AuthorizationRequest, BatchAuthorizationRequest, BetterIamOptions,
    Toggle, check_decoded, resolve_config,
};
use crate::plugins::validate_plugins;
use crate::port::{Callback, not_ported};
use crate::principals::create_principals;
use crate::retention::{Retention, create_retention};
use crate::secrets::{SecretRotationOptions, SecretRotationResult, rotate_secrets};
use crate::self_check::{SelfCheck, create_self_check};
use crate::session_tokens::{SessionTokenClaims, SessionTokenError};
use crate::signal_receiver::{SignalsRuntime, create_signals_protocol, create_signals_runtime};
use crate::ssh::ssh_plugins;
use crate::token_signing::create_session_token_signer;
use crate::usage::create_usage_recorder;
use crate::utils::{date_now, hash, same_hash};
use crate::vc::vc_plugins;
use crate::web_identity::create_web_identity_verifier;

/// `IamSessionTokens`: IAM-signed session JWTs (`sts.jwt`): the issuer, the public keys downstream services verify
/// with, and an online, revocation-aware check.
pub struct IamSessionTokens {
    signer: Arc<dyn SessionTokenSigner>,
    ctx: Arc<ServerContext>,
}

impl IamSessionTokens {
    /// The `iss` of every session JWT, also the audience IAM itself requires.
    pub fn issuer(&self) -> &str {
        self.signer.issuer()
    }

    /// The public signing and verification keys, as served at `{basePath}/.well-known/jwks.json`.
    pub fn jwks(&self) -> Value {
        json!({ "keys": serde_json::to_value(self.signer.public_jwks()).unwrap_or(Value::Array(Vec::new())) })
    }

    /// Verifies a session JWT for `audience` (default: the issuer), then requires its stored session to be live: the
    /// row, its identity and every revocation condition are re-validated. A token that verifies but has been revoked
    /// fails with `SessionTokenError` reason `revoked`.
    pub async fn verify(
        &self,
        token: &str,
        audience: Option<&str>,
    ) -> IamResult<SessionTokenClaims> {
        let claims = self.signer.verify(token, audience).await?;
        let ctx = &self.ctx;
        let revoked = || IamError::from(SessionTokenError::new("revoked", None));
        let checked = ctx
            .store
            .transaction(|tx| {
                let claims = &claims;
                async move {
                    let session: Option<Session> = match tx.get("sessions", &claims.sid).await? {
                        Some(record) => Some(crate::port::decode(record)?),
                        None => None,
                    };
                    let Some(session) = session.filter(|session| {
                        session.format.as_deref() == Some("jwt")
                            && session.kind.as_str() == claims.kind
                            && session.identity_id == claims.sub
                            && session.tenant_id == claims.tid
                            && same_hash(&session.token_hash, &hash(token))
                            && session.expires_at > ctx.now()
                    }) else {
                        return Err(revoked());
                    };
                    let identity: Option<Identity> =
                        match tx.get("identities", &session.identity_id).await? {
                            Some(record) => Some(crate::port::decode(record)?),
                            None => None,
                        };
                    let Some(identity) = identity.filter(|identity| {
                        identity.status == IdentityStatus::Active && !ctx.identity_expired(identity)
                    }) else {
                        return Err(revoked());
                    };
                    ctx.principals()?
                        .current_principal(
                            &tx,
                            &AuthenticatedPrincipal {
                                identity,
                                session,
                                device_proof: None,
                            },
                        )
                        .await?;
                    Ok(())
                }
            })
            .await;
        match checked {
            Ok(()) => Ok(claims),
            Err(_) => Err(revoked()),
        }
    }
}

/// Where the HTTP handler is mounted, for framework integrations that call it server-side (`endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub origin: String,
    pub base_path: String,
    pub secure: bool,
    /// The handler's cookie settings, so code that writes its own session cookies can match them.
    pub cookie_same_site: String,
    pub persistent_cookies: bool,
}

/// `hosts`: organization sign-in addresses and regions, for framework integrations and edge routing.
pub struct HostsRuntime {
    ctx: Arc<ServerContext>,
}

impl HostsRuntime {
    /// This deployment's region, when `regions` is configured.
    pub fn region(&self) -> Option<String> {
        self.ctx
            .config
            .regions
            .as_ref()
            .map(|regions| regions.current.clone())
    }

    /// Whether organizations may verify custom hostnames (`hosts.customHostnames`).
    pub fn custom_hostnames(&self) -> bool {
        self.ctx.config.hosts.custom_hostnames
    }

    /// The organization an address belongs to; None for the deployment's own and unknown hosts.
    pub async fn resolve(&self, host: &str) -> IamResult<Option<HostMatch>> {
        self.ctx.hosts()?.resolve(host, None).await
    }

    /// An organization's canonical sign-in URL.
    pub async fn sign_in_url(&self, tenant_id: &str) -> IamResult<Option<String>> {
        self.ctx.hosts()?.sign_in_url(tenant_id).await
    }

    /// True when a TLS certificate may be issued for `hostname` (an on-demand TLS "ask" check).
    pub async fn allowed(&self, hostname: &str) -> IamResult<bool> {
        Ok(self.ctx.hosts()?.allowed(hostname).await)
    }
}

/// `betterIam(options)`'s result (`BetterIam`).
pub struct BetterIam {
    pub ctx: Arc<ServerContext>,
    pub api: Arc<Api>,
    pub auth: AuthService,
    pub auth_api: Arc<AuthApi>,
    pub http: Arc<Http>,
    pub lifecycle: Lifecycle,
    pub retention: Arc<Retention>,
    pub audit_archive: AuditArchive,
    pub certification_worker: CertificationWorker,
    pub federation: Federation,
    pub self_check: SelfCheck,
    pub features: FeatureEvaluator,
    pub inference: InferenceRuntime,
    pub a2a: A2aRuntime,
    pub billing: BillingRuntime,
    pub kms: KmsRuntime,
    pub pki: PkiRuntime,
    pub protection: ProtectionRuntime,
    pub vault: VaultRuntime,
    pub plan_resources: PlanRuntime,
    pub quotas: QuotasRuntime,
    pub privacy: PrivacyRuntime,
    pub workflows: WorkflowsRuntime,
    pub compliance: ComplianceRuntime,
    pub applications: ApplicationsRuntime,
    pub ssh: SshRuntime,
    pub verifiable_credentials: VcRuntime,
    pub ldap: LdapRuntime,
    pub signals: SignalsRuntime,
    pub licenses: LicensesRuntime,
    pub guests: GuestsRuntime,
    pub clearances: ClearancesRuntime,
    /// Prometheus-style counters and histograms when `observability.metrics` is enabled.
    pub metrics: Option<Arc<MetricsCollector>>,
    /// Session JWT keys and online verification; present only when `sts.jwt` is configured.
    pub session_tokens: Option<IamSessionTokens>,
    pub store: Arc<dyn IamStore>,
    pub endpoint: Endpoint,
    pub hosts: HostsRuntime,
}

/// `withSignInUrl(send)`: with organization addresses or regions, every email and SMS names its organization's
/// sign-in URL.
fn with_sign_in_url(
    send: better_iam_auth::DeliveryFn,
    slot: Arc<OnceLock<Weak<ServerContext>>>,
) -> better_iam_auth::DeliveryFn {
    Arc::new(move |message: DeliveryMessage| {
        let send = send.clone();
        let ctx = slot.get().and_then(Weak::upgrade);
        Box::pin(async move {
            let Some(ctx) = ctx else {
                return send(message).await;
            };
            if !ctx.config.hosts.enabled && ctx.config.regions.is_none() {
                return send(message).await;
            }
            let sign_in_url = match ctx.hosts() {
                Ok(hosts) => hosts.sign_in_url(&message.tenant_id).await.ok().flatten(),
                Err(_) => None,
            };
            match sign_in_url {
                Some(url) => {
                    send(DeliveryMessage {
                        sign_in_url: Some(url),
                        ..message
                    })
                    .await
                }
                None => send(message).await,
            }
        }) as BoxFuture<'static, Result<(), DeliveryError>>
    })
}

fn not_attached() -> IamError {
    IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)
}

/// `betterIam(options)`: composes the IAM server. Configuration problems fail with INVALID_CONFIG (and the codes the
/// module validators use), in the TypeScript order.
pub fn better_iam(options: BetterIamOptions) -> IamResult<BetterIam> {
    let config = resolve_config(&options)?;
    let store = options
        .database
        .clone()
        .ok_or_else(|| IamError::new("INVALID_CONFIG", "database is required"))?;
    // Built-in modules that extend the catalog (inference: the `model` type and `inference:invoke`) come last.
    let mut plugins: Vec<Arc<dyn IamPlugin>> = options.plugins.clone().unwrap_or_default();
    plugins.extend(inference_plugins(&options)?);
    plugins.extend(ssh_plugins(&options)?);
    plugins.extend(vc_plugins(&options)?);
    let catalog = Catalog::new(&options, &plugins, &config)?;
    validate_plugins(&plugins, &catalog)?;
    let injected = options
        .authentication
        .as_ref()
        .and_then(|authentication| authentication.now.clone());
    let now: NowFn = match injected {
        Some(now) => now,
        None => Arc::new(date_now),
    };
    // Session JWT keys are validated here, so a bad `sts.jwt` fails construction with INVALID_CONFIG.
    let issuer = format!("{}{}", config.origin(), config.base_path);
    let session_tokens = create_session_token_signer(
        options.sts.as_ref().and_then(|sts| sts.jwt.as_ref()),
        &issuer,
        now.clone(),
    )?;
    // Authentication events fan out through the event service, which is attached to the context below.
    let slot: Arc<OnceLock<Weak<ServerContext>>> = Arc::default();
    let authentication = options.authentication.clone().unwrap_or_default();
    let mut auth_options = AuthOptions::new(
        store.clone(),
        options.secret.clone(),
        options.base_url.clone(),
    );
    auth_options.previous_secrets = options.previous_secrets.clone();
    auth_options.trusted_origins = options.trusted_origins.clone();
    auth_options.app_name = authentication.app_name.clone();
    auth_options.sign_up_enabled = authentication.sign_up_enabled;
    auth_options.require_email_verification = authentication.require_email_verification;
    auth_options.email_password = authentication.email_password;
    auth_options.passwordless_email = authentication.passwordless_email;
    auth_options.passwordless_sms = authentication.passwordless_sms;
    auth_options.send_email = authentication
        .send_email
        .clone()
        .map(|send| with_sign_in_url(send, slot.clone()));
    auth_options.send_sms = authentication
        .send_sms
        .clone()
        .map(|send| with_sign_in_url(send, slot.clone()));
    auth_options.max_delivery_attempts = authentication.max_delivery_attempts;
    auth_options.session_lifetime_ms = authentication.session_lifetime_ms;
    auth_options.session_idle_timeout_ms = authentication.session_idle_timeout_ms;
    auth_options.recent_authentication_ms = authentication.recent_authentication_ms;
    auth_options.trusted_device_lifetime_ms = authentication.trusted_device_lifetime_ms;
    auth_options.sign_in_notifications = authentication.sign_in_notifications;
    auth_options.mfa_email_codes = authentication.mfa_email_codes;
    auth_options.failed_sign_in_alerts = authentication.failed_sign_in_alerts;
    auth_options.rate_limits = authentication.rate_limits.clone();
    auth_options.require_mfa = authentication.require_mfa.clone();
    auth_options.passkeys =
        authentication
            .passkeys
            .clone()
            .map(|passkeys| better_iam_auth::PasskeyOptions {
                rp_id: passkeys.rp_id,
                rp_name: passkeys.rp_name,
            });
    auth_options.now = authentication.now.clone();
    auth_options.password_policy = authentication.password_policy.clone();
    let audit_slot = slot.clone();
    auth_options.on_audit = Some(Arc::new(move |tx: Arc<dyn IamStore>, event| {
        let ctx = audit_slot.get().and_then(Weak::upgrade);
        Box::pin(async move {
            match ctx {
                Some(ctx) => ctx.events()?.fan_out(&tx, &event).await,
                None => Ok(()),
            }
        })
    }));
    let webhook_slot = slot.clone();
    auth_options.deliver_webhook = Some(Arc::new(move |message: DeliveryMessage| {
        let ctx = webhook_slot.get().and_then(Weak::upgrade);
        Box::pin(async move {
            match ctx {
                Some(ctx) => ctx.events()?.deliver_webhook_message(message).await,
                None => Ok(()),
            }
        }) as BoxFuture<'static, Result<(), DeliveryError>>
    }));
    let auth = create_auth(auth_options)?;
    let metrics_options = options
        .observability
        .as_ref()
        .and_then(|observability| observability.metrics.clone());
    let metrics = match &metrics_options {
        Some(Toggle::Flag(false)) | None => None,
        Some(Toggle::Flag(true)) => Some(Arc::new(create_metrics(&MetricsOptions::default())?)),
        Some(Toggle::Options(settings)) => Some(Arc::new(create_metrics(settings)?)),
    };
    let on_span = options
        .observability
        .as_ref()
        .and_then(|observability| observability.on_span.clone());
    let observe = create_observer(match (&metrics, on_span) {
        (Some(metrics), on_span) => {
            let metrics = metrics.clone();
            Some(Arc::new(move |span: &IamSpan| {
                metrics.on_span(span);
                if let Some(on_span) = &on_span {
                    on_span(span);
                }
            }))
        }
        (None, on_span) => on_span,
    });
    let options = Arc::new(options);
    let ctx = create_context(ContextBase {
        options: options.clone(),
        config: Arc::new(config),
        store: store.clone(),
        auth: auth.clone(),
        plugins,
        catalog: Arc::new(catalog),
        now: now.clone(),
        observe: observe.clone(),
    });
    let _ = slot.set(Arc::downgrade(&ctx));
    if let Some(signer) = &session_tokens {
        ctx.attach_session_tokens(signer.clone());
    }
    ctx.attach_hosts(create_hosts(&ctx));
    // The external-token verifier exists only while web-identity federation is enabled.
    if ctx.config.sts.web_identity.enabled {
        let fetch_json = options
            .sts
            .as_ref()
            .and_then(|sts| sts.web_identity.as_ref())
            .and_then(|web| web.fetch_json.clone());
        let self_issuer = session_tokens
            .as_ref()
            .map(|signer| signer.issuer().to_owned())
            .unwrap_or_else(|| issuer.clone());
        ctx.attach_web_identity(create_web_identity_verifier(
            &ctx.config.sts.web_identity,
            fetch_json,
            now.clone(),
            &self_issuer,
        )?);
    }
    ctx.attach_events(create_events(&ctx));
    ctx.attach_decisions(create_decisions(&ctx));
    ctx.attach_principals(create_principals(&ctx));
    ctx.attach_operations(create_operations(&ctx));
    ctx.attach_flows(Arc::new(create_flows(&ctx)?));
    ctx.attach_usage(create_usage_recorder(&ctx)?);
    // The billing ledger; validates the `billing` option now, so a bad value fails construction with INVALID_CONFIG.
    ctx.attach_billing(crate::billing_service::billing_service_of(&ctx)?.hooks());
    // Wallet-facing issuer endpoints and the Shared Signals push endpoint.
    let vc_enabled = options
        .verifiable_credentials
        .as_ref()
        .is_some_and(|toggle| toggle.enabled());
    if vc_enabled {
        let protocol = create_vc_protocol(&ctx)?;
        ctx.mounted_protocols
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(protocol);
    }
    let signals = create_signals_protocol(&ctx)?;
    ctx.mounted_protocols
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(signals);
    // In-process calls that carry request headers record and judge the same client the HTTP handler would.
    let client_ctx = Arc::downgrade(&ctx);
    let client_of: ClientOf = Arc::new(move |headers: &[(String, String)]| {
        let ctx = client_ctx.upgrade()?;
        client_from_headers(
            ctx.options.http.as_ref(),
            Some(headers),
            ctx.config.base_url.as_str(),
        )
    });
    let auth_api = create_auth_api(auth.clone(), Some(observe.clone()), Some(client_of));
    let api = Arc::new(create_api(&ctx, auth_api.clone())?);
    let lifecycle = create_lifecycle(&ctx);
    let retention = Arc::new(create_retention(&ctx)?);
    let audit_archive = create_audit_archive(&ctx)?;
    let certification_worker = create_certification_worker(&ctx)?;
    let federation = create_federation(&ctx, api.bindings.clone())?;
    let metrics_settings = match &metrics_options {
        Some(Toggle::Options(settings)) => Some(settings.clone()),
        _ => None,
    };
    let http = create_http(
        &ctx,
        api.clone(),
        auth_api.clone(),
        HttpExtras {
            metrics: metrics.clone(),
            metrics_token: metrics_settings
                .as_ref()
                .and_then(|settings| settings.bearer_token.clone()),
            metrics_gauges: metrics_settings
                .as_ref()
                .and_then(|settings| settings.gauges)
                .unwrap_or(false),
        },
    )?;
    let count_retention = retention.clone();
    let count_due: Callback = Arc::new(move |args: Vec<Value>| {
        let retention = count_retention.clone();
        Box::pin(async move {
            let options: crate::self_check::DueOptions =
                serde_json::from_value(args.into_iter().next().unwrap_or(json!({})))
                    .map_err(|_| crate::js::internal_error())?;
            let counts = retention.count_due(&options).await?;
            Ok(serde_json::to_value(counts).unwrap_or(Value::Null))
        })
    });
    let sample_ctx = Arc::downgrade(&ctx);
    let sample_secrets: Callback = Arc::new(move |args: Vec<Value>| {
        let ctx = sample_ctx.upgrade();
        Box::pin(async move {
            let ctx = ctx.ok_or_else(not_attached)?;
            let limit = args.first().and_then(Value::as_f64);
            let report = rotate_secrets(
                &ctx,
                &SecretRotationOptions {
                    dry_run: true,
                    batch_size: None,
                    limit,
                },
            )
            .await?;
            Ok(serde_json::to_value(report).unwrap_or(Value::Null))
        })
    });
    let self_check = create_self_check(&ctx, count_due, sample_secrets)?;
    let iam = BetterIam {
        api,
        auth,
        auth_api,
        http,
        lifecycle,
        retention,
        audit_archive,
        certification_worker,
        federation,
        self_check,
        features: create_feature_evaluator(&ctx)?,
        inference: create_inference_runtime(&ctx)?,
        a2a: create_a2a_runtime(&ctx)?,
        billing: create_billing_runtime(&ctx)?,
        kms: create_kms_runtime(&ctx)?,
        pki: create_pki_runtime(&ctx)?,
        protection: create_protection_runtime(&ctx)?,
        vault: create_vault_runtime(&ctx)?,
        plan_resources: create_plan_runtime(&ctx)?,
        quotas: create_quotas_runtime(&ctx)?,
        privacy: create_privacy_runtime(&ctx)?,
        workflows: create_workflows_runtime(&ctx)?,
        compliance: create_compliance_runtime(&ctx)?,
        applications: create_applications_runtime(&ctx)?,
        ssh: create_ssh_runtime(&ctx)?,
        verifiable_credentials: create_vc_runtime(&ctx)?,
        ldap: create_ldap_runtime(&ctx)?,
        signals: create_signals_runtime(&ctx)?,
        licenses: create_licenses_runtime(&ctx)?,
        guests: create_guests_runtime(&ctx)?,
        clearances: create_clearances_runtime(&ctx)?,
        metrics,
        session_tokens: session_tokens.map(|signer| IamSessionTokens {
            signer,
            ctx: ctx.clone(),
        }),
        store,
        endpoint: Endpoint {
            origin: ctx.config.origin(),
            base_path: ctx.config.base_path.clone(),
            secure: ctx.config.https(),
            cookie_same_site: options
                .http
                .as_ref()
                .and_then(|http| http.cookie_same_site.clone())
                .unwrap_or_else(|| "lax".into()),
            persistent_cookies: options
                .http
                .as_ref()
                .and_then(|http| http.persistent_cookies)
                .unwrap_or(true),
        },
        hosts: HostsRuntime { ctx: ctx.clone() },
        ctx,
    };
    // Members of a JSON configuration with no typed Rust form are refused once every module validator has run.
    check_decoded(&iam.ctx.options)?;
    Ok(iam)
}

impl BetterIam {
    /// `iam.authorize(request)`.
    pub async fn authorize(&self, request: &AuthorizationRequest) -> IamResult<Decision> {
        self.ctx.operations()?.authorize(request).await
    }

    /// `iam.authorizeMany(request)`.
    pub async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> IamResult<Vec<BatchResult>> {
        self.ctx.operations()?.authorize_many(request).await
    }

    /// `iam.listAccessible(request)`.
    pub async fn list_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> IamResult<AccessibleResources> {
        self.ctx.operations()?.list_accessible(request).await
    }

    /// `iam.require(request)`: ACCESS_DENIED (403) unless allowed.
    pub async fn require(&self, request: &AuthorizationRequest) -> IamResult<()> {
        self.ctx.operations()?.require_access(request).await
    }

    /// `iam.authenticate(credential)`.
    pub async fn authenticate(
        &self,
        credential: &CredentialInput,
    ) -> IamResult<AuthenticatedPrincipal> {
        self.ctx.principals()?.authenticate(credential).await
    }

    /// `iam.initialize()`: migrations and the startup backfills.
    pub async fn initialize(&self) -> IamResult<()> {
        self.lifecycle.initialize().await
    }

    /// `iam.bootstrap(input)`.
    pub async fn bootstrap(&self, input: &Value) -> IamResult<Value> {
        self.lifecycle.bootstrap(input).await
    }

    /// `iam.recoverRoot(input)`.
    pub async fn recover_root(&self, input: &Value) -> IamResult<Value> {
        self.lifecycle.recover_root(input).await
    }

    /// `iam.purgeDeleted(input?)`.
    pub async fn purge_deleted(&self, input: Option<&Value>) -> IamResult<Value> {
        self.lifecycle.purge_deleted(input).await
    }

    /// `iam.pruneAudit(input)`.
    pub async fn prune_audit(&self, input: &Value) -> IamResult<Value> {
        self.lifecycle.prune_audit(input).await
    }

    /// `iam.archiveAudit(input?)`: copies new audit events, verified and in chain order, to `auditArchive`.
    pub async fn archive_audit(&self, input: Option<&Value>) -> IamResult<Value> {
        self.audit_archive.archive_audit(input).await
    }

    /// `iam.sweepExpired(options?)`: deletes expired sessions, protocol artifacts, and old delivery records.
    pub async fn sweep_expired(&self, options: Option<&Value>) -> IamResult<Value> {
        self.retention.sweep_expired(options).await
    }

    /// `iam.selfCheck(options?)`.
    pub async fn self_check(&self, options: Option<&Value>) -> IamResult<Value> {
        self.self_check.run(options).await
    }

    /// `iam.sendAccessDigest(input?)`.
    pub async fn send_access_digest(&self, input: Option<&Value>) -> IamResult<Value> {
        self.lifecycle.send_access_digest(input).await
    }

    /// `iam.sendExpiryReminders(input?)`.
    pub async fn send_expiry_reminders(&self, input: Option<&Value>) -> IamResult<Value> {
        self.lifecycle.send_expiry_reminders(input).await
    }

    /// `iam.reconcilePackages(input?)`.
    pub async fn reconcile_packages(&self, input: Option<&Value>) -> IamResult<Value> {
        self.lifecycle.reconcile_packages(input).await
    }

    /// `iam.closeOverdueCertifications(input?)`.
    pub async fn close_overdue_certifications(&self, input: Option<&Value>) -> IamResult<Value> {
        self.certification_worker
            .close_overdue_certifications(input)
            .await
    }

    /// `iam.closeOverdueTeamReviews(input?)`.
    pub async fn close_overdue_team_reviews(&self, input: Option<&Value>) -> IamResult<Value> {
        crate::team_reviews::close_overdue_team_reviews(&self.ctx, input).await
    }

    /// `iam.checkInvariants(input?)`.
    pub async fn check_invariants(&self, input: Option<&Value>) -> IamResult<Value> {
        crate::invariants::check_invariants(&self.ctx, input).await
    }

    /// `iam.detectThreats(input?)`.
    pub async fn detect_threats(&self, input: Option<&Value>) -> IamResult<Value> {
        let run = crate::threat_engine::detect_threats(&self.ctx, input).await?;
        serde_json::to_value(run).map_err(|_| crate::js::internal_error())
    }

    /// `iam.flushAccessUsage()`: writes buffered access usage now; call it before shutting down.
    pub async fn flush_access_usage(&self) -> IamResult<Value> {
        let written = self.ctx.usage()?.flush().await?;
        Ok(json!({ "written": crate::js::number(written) }))
    }

    /// `iam.dispatchAuditHooks()`.
    pub async fn dispatch_audit_hooks(&self) -> IamResult<Value> {
        let dispatched = self.ctx.events()?.dispatch().await?;
        Ok(json!({ "dispatched": dispatched.dispatched }))
    }

    /// `iam.callPlugin(credential, input)`.
    pub async fn call_plugin(
        &self,
        credential: &CredentialInput,
        input: crate::contracts::PluginCall,
    ) -> IamResult<Value> {
        self.ctx.operations()?.call_plugin(credential, input).await
    }

    /// `iam.assertionKey()`: the derived key downstream services use with `verifyAssertion`.
    pub fn assertion_key(&self) -> String {
        assertion_key(&self.ctx.options.secret)
    }

    /// `iam.assertionKeys()`: the current assertion key first, then those of `previousSecrets`.
    pub fn assertion_keys(&self) -> Vec<String> {
        std::iter::once(&self.ctx.options.secret)
            .chain(self.ctx.options.previous_secrets.iter().flatten())
            .map(|secret| assertion_key(secret))
            .collect()
    }

    /// `iam.rotateSecrets(options)`: re-seals values encrypted with `previousSecrets` using `secret`.
    pub async fn rotate_secrets(
        &self,
        options: &SecretRotationOptions,
    ) -> IamResult<SecretRotationResult> {
        rotate_secrets(&self.ctx, options).await
    }

    /// `iam.handler(request)`.
    pub async fn handler(
        &self,
        request: crate::options::HttpRequest,
    ) -> crate::options::HttpResponse {
        self.http.handler(request).await
    }

    /// `iam.useProtocol(protocol)`.
    pub fn use_protocol(&self, protocol: Arc<dyn crate::http::ProtocolService>) {
        self.http.use_protocol(protocol);
    }

    /// `iam.protocolHost`: trusted callbacks handed to protocol packages (OAuth, SAML, SCIM).
    pub fn protocol_host(&self) -> &Federation {
        &self.federation
    }

    /// The not-ported placeholder for members the composition has no Rust form of yet.
    pub fn unsupported(&self, member: &str) -> IamError {
        not_ported(&format!("index.ts {member}"))
    }
}
