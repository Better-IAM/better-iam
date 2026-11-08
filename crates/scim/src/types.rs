//! Port of `packages/scim/src/types.ts`: schema URNs, limits, and the service configuration.

use std::sync::Arc;

use better_iam_core::{CredentialInput, IamResult, IamStore, Record, ResourceRef};
use futures::future::BoxFuture;
use serde_json::{Map, Value};

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SEARCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
pub const BULK_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub const BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
/// Bulk limits advertised in ServiceProviderConfig and enforced by the /Bulk endpoint.
pub const BULK_MAX_OPERATIONS: usize = 100;
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// `ObjectValue`: a JSON object.
pub type ObjectValue = Map<String, Value>;
/// A store handle (the root store or an open transaction).
pub type Store = Arc<dyn IamStore>;

/// `ResourceType`: the provisioned resource kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Users,
    Groups,
}

impl ResourceType {
    /// The endpoint name (`Users`, `Groups`).
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceType::Users => "Users",
            ResourceType::Groups => "Groups",
        }
    }

    /// The endpoint of a name, if it is one.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Users" => Some(ResourceType::Users),
            "Groups" => Some(ResourceType::Groups),
            _ => None,
        }
    }
}

/// The provisioned attributes handed to `mapAttributes` (`ProvisionedUser`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionedUser {
    pub user_name: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub active: bool,
    pub title: Option<String>,
    /// The enterprise user extension (department, division, manager, ...) as provisioned.
    pub enterprise: Option<ObjectValue>,
    pub emails: Option<Vec<Value>>,
    pub name: Option<ObjectValue>,
}

/// The argument of `syncRoleMappings`.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleMappingSync {
    pub tenant_id: String,
    pub connection_id: String,
    pub group_id: String,
    pub identity_ids: Vec<String>,
    pub role_ids: Vec<String>,
    /// The administrator's credential, present only when an administrator changed the mapping.
    pub credential: Option<CredentialInput>,
}

/// The argument of `identityStatusChanged`.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityStatusChange {
    pub tenant_id: String,
    pub connection_id: String,
    pub identity_id: String,
}

/// The argument of `groupDeleted`.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupDeletion {
    pub tenant_id: String,
    pub connection_id: String,
    pub group_id: String,
}

/// `authorize(credential, action, resource)`: must authenticate the credential and fail on a denied IAM permission.
pub type AuthorizeFn = Arc<
    dyn Fn(CredentialInput, String, ResourceRef) -> BoxFuture<'static, IamResult<()>> + Send + Sync,
>;
/// `authenticate(credential)`: the authenticated identity's ID (`principal.identity.id`).
pub type AuthenticateFn =
    Arc<dyn Fn(CredentialInput) -> BoxFuture<'static, IamResult<String>> + Send + Sync>;
/// `mapAttributes(user)`: the identity attributes of a provisioned user; None leaves attributes untouched.
pub type MapAttributesFn =
    Arc<dyn Fn(&ProvisionedUser) -> IamResult<Option<ObjectValue>> + Send + Sync>;
/// `validateIdentityAttributes(attributes)`: validates mapped attributes against the declared identity attributes.
pub type ValidateAttributesFn = Arc<dyn Fn(&ObjectValue) -> IamResult<ObjectValue> + Send + Sync>;
/// `recordAudit(tx, event)`: records an audit event and fans it out (webhooks, plugins, subscribers).
pub type RecordAuditFn =
    Arc<dyn Fn(Store, Record) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;
/// `syncRoleMappings(tx, input)`: trusted server callback, called transactionally.
pub type SyncRoleMappingsFn =
    Arc<dyn Fn(Store, RoleMappingSync) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;
/// `identityStatusChanged(tx, input)`: trusted server callback, called in the transaction.
pub type IdentityStatusChangedFn =
    Arc<dyn Fn(Store, IdentityStatusChange) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;
/// `groupDeleted(tx, input)`: trusted server callback, called in the transaction.
pub type GroupDeletedFn =
    Arc<dyn Fn(Store, GroupDeletion) -> BoxFuture<'static, IamResult<()>> + Send + Sync>;

/// `ScimConfig`.
#[derive(Clone)]
pub struct ScimConfig {
    pub store: Store,
    /// Must authenticate the credential and fail on a denied IAM permission.
    pub authorize: AuthorizeFn,
    pub authenticate: AuthenticateFn,
    /// Default `/scim/v2`.
    pub base_path: Option<String>,
    /// Where `handler` serves the JSON administration API for connections (`{adminBasePath}/connections/{list,create,
    /// rotate,revoke,groups,mappings}`), default `/scim/admin`. Must be absolute and must not overlap `basePath`.
    pub admin_base_path: Option<String>,
    /// Maps the enterprise extension's `manager.value` (a SCIM user ID, `externalId`, or `userName` of the same
    /// connection) to `Identity.managerId`, back-filling reports provisioned before their manager. Managers an
    /// administrator set are never cleared by SCIM. Default true.
    pub map_manager: Option<bool>,
    /// What happens to attributes this service provider does not store: `ignore` (default) or `reject` (400
    /// `mutability`). Any other value fails construction.
    pub unsupported_attributes: Option<String>,
    pub map_attributes: Option<MapAttributesFn>,
    pub validate_identity_attributes: Option<ValidateAttributesFn>,
    /// Without it events are only appended to the audit chain.
    pub record_audit: Option<RecordAuditFn>,
    /// Called transactionally only for administrator-configured role mappings.
    pub sync_role_mappings: Option<SyncRoleMappingsFn>,
    pub identity_status_changed: Option<IdentityStatusChangedFn>,
    pub group_deleted: Option<GroupDeletedFn>,
}

impl ScimConfig {
    /// A configuration with the required members and every option at its default.
    pub fn new(store: Store, authorize: AuthorizeFn, authenticate: AuthenticateFn) -> Self {
        Self {
            store,
            authorize,
            authenticate,
            base_path: None,
            admin_base_path: None,
            map_manager: None,
            unsupported_attributes: None,
            map_attributes: None,
            validate_identity_attributes: None,
            record_audit: None,
            sync_role_mappings: None,
            identity_status_changed: None,
            group_deleted: None,
        }
    }
}

/// An [`AuthorizeFn`] from an async closure.
pub fn authorize_fn<F, Fut>(f: F) -> AuthorizeFn
where
    F: Fn(CredentialInput, String, ResourceRef) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = IamResult<()>> + Send + 'static,
{
    Arc::new(move |credential, action, resource| Box::pin(f(credential, action, resource)))
}

/// An [`AuthenticateFn`] from an async closure.
pub fn authenticate_fn<F, Fut>(f: F) -> AuthenticateFn
where
    F: Fn(CredentialInput) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = IamResult<String>> + Send + 'static,
{
    Arc::new(move |credential| Box::pin(f(credential)))
}
