//! Errors of the provider: the OAuth protocol errors of `oidc-provider` (`errors.InvalidGrant`, ...) beside
//! [`IamError`]s. Protocol errors render as `{ error, error_description }` with their status; anything else is a
//! server error.

use better_iam_core::IamError;

/// An `oidc-provider` protocol error (`OIDCProviderError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcError {
    pub status: u16,
    /// The `error` code (`invalid_grant`).
    pub error: String,
    pub description: Option<String>,
    pub scope: Option<String>,
    /// `error_detail`: diagnostics, never sent to the client.
    pub detail: Option<String>,
    pub allow_redirect: bool,
    /// The class name, for the checks that tell classes apart (`InvalidDpopProof`, `SessionNotFound`, ...).
    pub class: &'static str,
}

impl OidcError {
    fn base(status: u16, error: &str, class: &'static str) -> Self {
        Self {
            status,
            error: error.to_owned(),
            description: None,
            scope: None,
            detail: None,
            allow_redirect: true,
            class,
        }
    }

    /// The `E(message, defaultDescription)` classes: `new X(description?)`.
    fn simple(
        error: &str,
        class: &'static str,
        default: Option<&str>,
        description: Option<&str>,
    ) -> Self {
        let mut out = Self::base(400, error, class);
        out.description = description.or(default).map(str::to_owned);
        out
    }

    /// `new InvalidRequest(description?, code?)`.
    pub fn invalid_request(description: impl Into<String>) -> Self {
        let mut out = Self::base(400, "invalid_request", "InvalidRequest");
        let description = description.into();
        out.description = Some(if description.is_empty() {
            "request is invalid".to_owned()
        } else {
            description
        });
        out
    }

    /// `new InvalidRequest(description, status)`.
    pub fn invalid_request_status(description: impl Into<String>, status: u16) -> Self {
        let mut out = Self::invalid_request(description);
        out.status = status;
        out
    }

    /// `new SessionNotFound(description)` (an `InvalidRequest`).
    pub fn session_not_found(description: impl Into<String>) -> Self {
        let mut out = Self::invalid_request(description);
        out.class = "SessionNotFound";
        out
    }

    /// `new InvalidGrant(detail?)`: the description stays `grant request is invalid`.
    pub fn invalid_grant(detail: impl Into<String>) -> Self {
        let mut out = Self::base(400, "invalid_grant", "InvalidGrant");
        out.description = Some("grant request is invalid".into());
        let detail = detail.into();
        if !detail.is_empty() {
            out.detail = Some(detail);
        }
        out
    }

    /// `new InvalidClientAuth(detail?)`.
    pub fn invalid_client_auth(detail: impl Into<String>) -> Self {
        let mut out = Self::base(401, "invalid_client", "InvalidClientAuth");
        out.description = Some("client authentication failed".into());
        let detail = detail.into();
        if !detail.is_empty() {
            out.detail = Some(detail);
        }
        out
    }

    /// `new InvalidToken(detail?)`.
    pub fn invalid_token(detail: impl Into<String>) -> Self {
        let mut out = Self::base(401, "invalid_token", "InvalidToken");
        out.description = Some("invalid token provided".into());
        let detail = detail.into();
        if !detail.is_empty() {
            out.detail = Some(detail);
        }
        out
    }

    /// `NoAccessTokenProvided` (an `InvalidToken`).
    pub fn no_access_token() -> Self {
        let mut out = Self::invalid_token("no access token provided");
        out.description = Some("no access token provided".into());
        out.class = "NoAccessTokenProvided";
        out
    }

    /// `new InvalidClientMetadata(description)`: `invalid_redirect_uri` for redirect URI problems.
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        let description = description.into();
        let error = if description.starts_with("redirect_uris") {
            "invalid_redirect_uri"
        } else {
            "invalid_client_metadata"
        };
        let mut out = Self::base(400, error, "InvalidClientMetadata");
        out.description = Some(description);
        out
    }

    /// `new InvalidScope(description, scope)`.
    pub fn invalid_scope(description: impl Into<String>, scope: Option<String>) -> Self {
        let mut out = Self::base(400, "invalid_scope", "InvalidScope");
        out.description = Some(description.into());
        out.scope = scope;
        out
    }

    /// `new InsufficientScope(description, scope)`.
    pub fn insufficient_scope(description: impl Into<String>, scope: Option<String>) -> Self {
        let mut out = Self::base(403, "insufficient_scope", "InsufficientScope");
        out.description = Some(description.into());
        out.scope = scope;
        out
    }

    /// `new InvalidRedirectUri()`.
    pub fn invalid_redirect_uri() -> Self {
        let mut out = Self::base(400, "invalid_redirect_uri", "InvalidRedirectUri");
        out.description =
            Some("redirect_uri did not match any of the client's registered redirect_uris".into());
        out.allow_redirect = false;
        out
    }

    pub fn access_denied(description: Option<&str>) -> Self {
        Self::simple("access_denied", "AccessDenied", None, description)
    }
    pub fn authorization_pending() -> Self {
        Self::simple(
            "authorization_pending",
            "AuthorizationPending",
            Some(
                "authorization request is still pending as the end-user hasn't yet completed the user interaction steps",
            ),
            None,
        )
    }
    pub fn expired_token(description: Option<&str>) -> Self {
        Self::simple("expired_token", "ExpiredToken", None, description)
    }
    pub fn invalid_client(description: Option<&str>) -> Self {
        Self::simple("invalid_client", "InvalidClient", None, description)
    }
    pub fn invalid_dpop_proof(description: &str) -> Self {
        Self::simple(
            "invalid_dpop_proof",
            "InvalidDpopProof",
            None,
            Some(description),
        )
    }
    pub fn use_dpop_nonce(description: &str) -> Self {
        Self::simple("use_dpop_nonce", "UseDpopNonce", None, Some(description))
    }
    pub fn invalid_request_object(description: &str) -> Self {
        Self::simple(
            "invalid_request_object",
            "InvalidRequestObject",
            None,
            Some(description),
        )
    }
    pub fn invalid_request_uri(description: &str) -> Self {
        Self::simple(
            "invalid_request_uri",
            "InvalidRequestUri",
            None,
            Some(description),
        )
    }
    pub fn invalid_target(description: Option<&str>) -> Self {
        Self::simple(
            "invalid_target",
            "InvalidTarget",
            Some("resource indicator is missing, or unknown"),
            description,
        )
    }
    pub fn login_required(description: Option<&str>) -> Self {
        Self::simple("login_required", "LoginRequired", None, description)
    }
    pub fn consent_required(description: Option<&str>) -> Self {
        Self::simple("consent_required", "ConsentRequired", None, description)
    }
    pub fn interaction_required(description: Option<&str>) -> Self {
        Self::simple(
            "interaction_required",
            "InteractionRequired",
            None,
            description,
        )
    }
    pub fn registration_not_supported() -> Self {
        Self::simple(
            "registration_not_supported",
            "RegistrationNotSupported",
            None,
            None,
        )
    }
    pub fn request_not_supported() -> Self {
        Self::simple("request_not_supported", "RequestNotSupported", None, None)
    }
    pub fn request_uri_not_supported() -> Self {
        Self::simple(
            "request_uri_not_supported",
            "RequestUriNotSupported",
            None,
            None,
        )
    }
    pub fn unsupported_grant_type() -> Self {
        Self::simple(
            "unsupported_grant_type",
            "UnsupportedGrantType",
            Some("unsupported grant_type requested"),
            None,
        )
    }
    pub fn unsupported_response_mode() -> Self {
        Self::simple(
            "unsupported_response_mode",
            "UnsupportedResponseMode",
            Some("unsupported response_mode requested"),
            None,
        )
    }
    pub fn unsupported_response_type() -> Self {
        Self::simple(
            "unsupported_response_type",
            "UnsupportedResponseType",
            Some("unsupported response_type requested"),
            None,
        )
    }
    pub fn unsupported_token_type(description: &str) -> Self {
        Self::simple(
            "unsupported_token_type",
            "UnsupportedTokenType",
            None,
            Some(description),
        )
    }

    /// `new CustomOIDCProviderError(error, description)`, or the named class when one exists (`errorMap`).
    pub fn from_code(error: &str, description: Option<&str>) -> Self {
        match error {
            "access_denied" => Self::access_denied(description),
            "login_required" => Self::login_required(description),
            "consent_required" => Self::consent_required(description),
            "interaction_required" => Self::interaction_required(description),
            "invalid_request" => Self::invalid_request(description.unwrap_or_default()),
            "invalid_client" => Self::invalid_client(description),
            "invalid_target" => Self::invalid_target(description),
            "expired_token" => Self::expired_token(description),
            _ => {
                let mut out = Self::base(400, error, "CustomOIDCProviderError");
                out.description = description.map(str::to_owned);
                out
            }
        }
    }

    pub fn is(&self, class: &str) -> bool {
        self.class == class
    }

    /// `errOut(error, state)`.
    pub fn out(&self, state: Option<&str>) -> serde_json::Map<String, serde_json::Value> {
        let mut out = serde_json::Map::new();
        out.insert("error".into(), self.error.clone().into());
        if let Some(description) = &self.description {
            out.insert("error_description".into(), description.clone().into());
        }
        if let Some(scope) = &self.scope {
            out.insert("scope".into(), scope.clone().into());
        }
        if let Some(state) = state {
            out.insert("state".into(), state.into());
        }
        out
    }
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

/// A provider failure: a protocol error or any other error.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderError {
    Oidc(OidcError),
    Iam(IamError),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Oidc(error) => write!(f, "{error}"),
            ProviderError::Iam(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<OidcError> for ProviderError {
    fn from(error: OidcError) -> Self {
        ProviderError::Oidc(error)
    }
}

impl From<IamError> for ProviderError {
    fn from(error: IamError) -> Self {
        ProviderError::Iam(error)
    }
}

impl ProviderError {
    pub fn oidc(&self) -> Option<&OidcError> {
        match self {
            ProviderError::Oidc(error) => Some(error),
            ProviderError::Iam(_) => None,
        }
    }

    /// `errOut`: exposed protocol errors keep their code; everything else is `server_error`.
    pub fn out(&self, state: Option<&str>) -> serde_json::Map<String, serde_json::Value> {
        match self {
            ProviderError::Oidc(error) if error.status < 500 => error.out(state),
            _ => {
                let mut out = serde_json::Map::new();
                out.insert("error".into(), "server_error".into());
                out.insert(
                    "error_description".into(),
                    "oops! something went wrong".into(),
                );
                if let Some(state) = state.filter(|state| !state.is_empty()) {
                    out.insert("state".into(), state.into());
                }
                out
            }
        }
    }

    /// `err.statusCode || 500`.
    pub fn status(&self) -> u16 {
        match self {
            ProviderError::Oidc(error) => error.status,
            ProviderError::Iam(_) => 500,
        }
    }

    /// The error as an [`IamError`] for callers outside the protocol (management functions): protocol errors keep
    /// their code as the message and their status.
    pub fn into_iam(self) -> IamError {
        match self {
            ProviderError::Iam(error) => error,
            ProviderError::Oidc(error) => IamError::with_status(
                error.error.clone(),
                error
                    .description
                    .clone()
                    .unwrap_or_else(|| error.error.clone()),
                error.status,
            ),
        }
    }
}

/// `Result` with [`ProviderError`].
pub type ProviderResult<T> = Result<T, ProviderError>;
