//! Agent2Agent (A2A) support for Better IAM (Rust), the counterpart of the `@better-iam/a2a` npm package:
//! IAM-attested agent cards ([`verify_agent_card`], [`discover_agent`], [`create_card_attestor`]), offline
//! verification of delegation tokens ([`verify_delegation_token`]) and an agent-side token cache
//! ([`create_delegation_token_cache`]), and authorization for A2A servers ([`create_a2a_gate`],
//! [`create_a2a_authorizer`]).

pub mod cards;
pub mod delegation_tokens;
pub mod error;
pub mod gate;
#[cfg(feature = "server")]
pub mod server;
pub mod transport;

pub use better_iam_core::{DelegationActor, DelegationTokenSummary};
pub use cards::{
    AGENT_ATTESTATION_URI, AgentAttestation, AgentCard, AgentCardError, AgentCardErrorReason,
    AgentCardSignature, AgentExtension, AgentSkill, CardAttestor, CardAttestorOptions, CardJwk,
    CardJwks, CardKeyResolver, CardKeys, CardSigner, CardSource, Clock, DiscoverAgentOptions,
    SignedCard, TrustedKeys, VerifiedAgentCard, VerifyAgentCardOptions, create_card_attestor,
    discover_agent, verify_agent_card,
};
pub use delegation_tokens::{
    DelegationTokenCache, DelegationTokenCacheOptions, DelegationTokenError,
    DelegationTokenErrorReason, DelegationTokenIssuer, IssuedDelegationToken, ReplayCheck,
    VerifyDelegationTokenOptions, create_delegation_token_cache, verify_delegation_token,
};
pub use error::A2aError;
pub use gate::{
    A2A_ACCESS_DENIED, A2A_CONFIRMATION_REQUESTED, A2aAuthorization, A2aAuthorizer, A2aCaller,
    A2aCheck, A2aConfirmation, A2aConfirmationRequest, A2aDecision, A2aDelegation, A2aDelegations,
    A2aGate, A2aGateOptions, A2aIam, A2aIamCaller, A2aIdentity, A2aOAuthCaller, A2aOAuthRequest,
    A2aOAuthToken, A2aOAuthVerifier, A2aPrincipal, A2aResourceRef, A2aRule, A2aSession,
    A2aTaskOwners, A2aTenant, HANDOFF_METADATA_KEY, MemoryTaskOwners, MemoryTaskOwnersOptions,
    Passthrough, RuleResource, UnlistedSkills, create_a2a_authorizer, create_a2a_gate, handoff_of,
    memory_task_owners, task_owner_of, with_handoff,
};
pub use transport::{
    Body, BodyError, Fetch, FetchFn, HttpFetch, RedirectPolicy, ResponseUrl, fetch_fn,
};
