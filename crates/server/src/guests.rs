//! Port of `packages/server/src/guests.ts`: B2B guest collaboration (the API is api/guests.rs). People from outside
//! the organization, or from another tenant, join as guests: invited by email, vouched for by a sponsor, given
//! limited access for a limited time that the sponsor renews (attests), and admitted only when the host's inbound and
//! the home organization's outbound cross-tenant access settings both allow it. A guest is an ordinary `kind: 'user'`
//! identity of the host tenant carrying the server-owned `Identity.guest` marker (never an attribute, never a new
//! kind), so everything tenant-local applies to guests unchanged. Policies see `principal.guest`,
//! `principal.guestSponsorId` and `principal.homeTenantId`, and a tenant's `guestBoundary` is a ceiling on every
//! guest's decisions there.
//!
//! Records are read and written as raw JSON (`Record`), so member order and members this port does not know survive
//! a round trip (a mixed fleet shares the database with TypeScript); the typed structs below decode them for reading.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, Identity,
    IdentityKind, IdentityStatus, Record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::domains::domain_name;
use crate::context::{ServerContext, Store};
use crate::port::decode;
use crate::validation::{email, text};

/// The collections this module owns, all tenant-scoped (lifecycle.ts purges them with their tenant).
pub static GUEST_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"invitations":"guestInvitations","accounts":"guestAccounts","settings":"crossTenantAccess"}),
);

/// `guestCollections.invitations`.
pub const INVITATIONS: &str = "guestInvitations";
/// `guestCollections.accounts`.
pub const ACCOUNTS: &str = "guestAccounts";
/// `guestCollections.settings`.
pub const SETTINGS: &str = "crossTenantAccess";

/// Guest lifetimes and list sizes: defaults and bounds, in days where they are durations.
pub static GUEST_LIMITS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"accessDays":90,"maxAccessDays":365,"reviewEveryDays":90,"minReviewEveryDays":7,"maxReviewEveryDays":365,"invitationDays":14,"maxInvitationDays":30,"reminderDays":14}),
);

/// `guestLimits` as typed constants.
pub mod limits {
    /// How long a guest keeps access after redeeming (or being attested), unless the tenant sets its own.
    pub const ACCESS_DAYS: f64 = 90.0;
    pub const MAX_ACCESS_DAYS: f64 = 365.0;
    /// How often the sponsor confirms that the guest still needs access, unless the tenant sets its own.
    pub const REVIEW_EVERY_DAYS: f64 = 90.0;
    pub const MIN_REVIEW_EVERY_DAYS: f64 = 7.0;
    pub const MAX_REVIEW_EVERY_DAYS: f64 = 365.0;
    /// How long an invitation can be redeemed, unless the inviter chooses 1 to 30 days.
    pub const INVITATION_DAYS: f64 = 14.0;
    pub const MAX_INVITATION_DAYS: f64 = 30.0;
    /// Sponsors are reminded this many days before a review is due or a guest's access ends.
    pub const REMINDER_DAYS: f64 = 14.0;
}

pub const GUEST_DAY_MS: f64 = 86400000.0;

fn find_all() -> FindOptions {
    FindOptions::default()
}

fn member_str<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// Where an invited address comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestOrigin {
    /// The address's domain.
    pub domain: String,
    /// The tenant that verified the domain, when another tenant did.
    pub home_tenant_id: Option<String>,
}

/// The stored cross-tenant access settings of one tenant (id = the tenant's id).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossTenantAccess {
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(rename = "inbound")]
    pub inbound: crate::guests::InboundGuestSettings,
    #[serde(rename = "outbound")]
    pub outbound: crate::guests::OutboundGuestSettings,
    /// How long a guest's access lasts after redemption or attestation, in days (1 to 365).
    #[serde(rename = "accessDays")]
    pub access_days: f64,
    /// How often the sponsor confirms a guest still needs access, in days (7 to 365).
    #[serde(rename = "reviewEveryDays")]
    pub review_every_days: f64,
    /// A ceiling applied to every guest's decisions in this tenant.
    #[serde(
        rename = "guestBoundary",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub guest_boundary: Option<better_iam_core::PolicyDocument>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One organization's entry in a partner list: `allow: true` admits it over the defaults, `false` refuses it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossTenantPartner {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "allow")]
    pub allow: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One guest's governance record (id = the guest identity's id), with top-level fields so guests can be found by
/// sponsor and status. Decisions read the identity's `guest` marker; this row carries the lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestAccount {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "sponsorId")]
    pub sponsor_id: String,
    #[serde(rename = "email")]
    pub email: String,
    /// The tenant that verified the guest's email domain, when another tenant had.
    #[serde(
        rename = "homeTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub home_tenant_id: Option<String>,
    #[serde(rename = "source")]
    pub source: String,
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
    #[serde(rename = "invitedBy")]
    pub invited_by: String,
    #[serde(rename = "redeemedAt")]
    pub redeemed_at: f64,
    /// The last time the sponsor (or an administrator) renewed the guest's access, and who did.
    #[serde(
        rename = "attestedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attested_at: Option<f64>,
    #[serde(
        rename = "attestedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attested_by: Option<String>,
    /// When the sponsor is next asked to confirm that the guest still needs access.
    #[serde(rename = "reviewDueAt")]
    pub review_due_at: f64,
    #[serde(rename = "status")]
    pub status: crate::guests::GuestAccountStatus,
    /// The sponsor left or can no longer sponsor guests; set a new one with `guests.setSponsor`.
    #[serde(
        rename = "sponsorMissing",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sponsor_missing: Option<bool>,
    /// When the tenant's owners were emailed about the missing sponsor (once per loss).
    #[serde(
        rename = "sponsorMissingNotifiedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sponsor_missing_notified_at: Option<f64>,
    #[serde(rename = "grants")]
    pub grants: crate::guests::GuestGrants,
    /// The end the invitation's grants were last given: the guest's access end at redemption, then at each renewal;
    /// absent once a conversion cleared it. Renewals move the grants still ending then, so an administrator changing
    /// the guest's own end in between (`identities.update`) does not leave them behind.
    #[serde(
        rename = "grantsEndAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub grants_end_at: Option<f64>,
    /// When the account stopped being active (expired, removed, converted), and who ended it.
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<f64>,
    #[serde(rename = "endedBy", default, skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<String>,
    /// Why an administrator removed the guest.
    #[serde(
        rename = "removalReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub removal_reason: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `active` while the guest may use their access; `expired` once it ended (the identity passed its `expiresAt`);
/// `removed` after `guests.remove` or offboarding; `converted` once the guest became an ordinary member.
pub type GuestAccountStatus = String;

/// What the invitation granted at redemption; attestation moves their end together with the guest's own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestGrants {
    #[serde(rename = "bindingIds")]
    pub binding_ids: Vec<String>,
    #[serde(rename = "membershipIds")]
    pub membership_ids: Vec<String>,
    #[serde(rename = "packageAssignmentIds")]
    pub package_assignment_ids: Vec<String>,
    /// The memberships the package assignments created at redemption. Renewals lengthen only these: a group a package
    /// gained since was never authorized for the guest (`packages.update` grants nothing). Absent on accounts redeemed
    /// before it was recorded, whose renewals lengthen the assignments' own memberships.
    #[serde(
        rename = "packageMembershipIds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_membership_ids: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An emailed invitation to join the tenant as a guest (`guests.invite`). The token is stored only as its SHA-256
/// hash. While pending, the invitation holds `uniqueKey` `pending:{email}`, so an address has at most one open
/// invitation per tenant. Its roles, groups and packages are granted at redemption under the inviter's authority,
/// for as long as the guest's access lasts, and only if the inviter could still grant them then.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestInvitation {
    /// The invited address, normalized; the guest identity is created with it at redemption.
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    /// The member who vouches for the guest.
    #[serde(rename = "sponsorId")]
    pub sponsor_id: String,
    /// Who sent the invitation; its grants are made under this person's authority, re-checked at redemption.
    #[serde(rename = "invitedBy")]
    pub invited_by: String,
    /// A note from the inviter, included in the email.
    #[serde(rename = "message", default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "roleIds")]
    pub role_ids: Vec<String>,
    #[serde(rename = "groupIds")]
    pub group_ids: Vec<String>,
    #[serde(rename = "packageIds")]
    pub package_ids: Vec<String>,
    /// The inviter's grant authority behind the roles and groups; absent when the invitation grants neither.
    #[serde(
        rename = "authorityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authority_id: Option<String>,
    /// How long the guest's access lasts from redemption, in days.
    #[serde(rename = "accessDays")]
    pub access_days: f64,
    /// The tenant that had verified the address's domain when the invitation was sent (a tenant-sourced guest).
    #[serde(
        rename = "homeTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub home_tenant_id: Option<String>,
    /// When the current token lapses (epoch milliseconds).
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    /// When the current token was sent: creation, or the last `resendInvitation`.
    #[serde(rename = "sentAt")]
    pub sent_at: f64,
    #[serde(rename = "status")]
    pub status: crate::guests::GuestInvitationStatus,
    #[serde(
        rename = "redeemedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub redeemed_at: Option<f64>,
    /// The guest identity the redemption created.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    /// Set when an administrator revoked the invitation (`revokeInvitation`).
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    /// Set when the invitation was revoked because its inviter or sponsor was disabled or left.
    #[serde(
        rename = "revokedReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_reason: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'pending' | 'redeemed' | 'revoked' | 'expired'`.
pub type GuestInvitationStatus = String;

/// A tenant's guest settings, stored or defaulted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestSettings {
    #[serde(rename = "inbound")]
    pub inbound: crate::guests::InboundGuestSettings,
    #[serde(rename = "outbound")]
    pub outbound: crate::guests::OutboundGuestSettings,
    /// How long a guest's access lasts after redemption or attestation, in days (1 to 365).
    #[serde(rename = "accessDays")]
    pub access_days: f64,
    /// How often the sponsor confirms a guest still needs access, in days (7 to 365).
    #[serde(rename = "reviewEveryDays")]
    pub review_every_days: f64,
    /// A ceiling applied to every guest's decisions in this tenant.
    #[serde(
        rename = "guestBoundary",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub guest_boundary: Option<better_iam_core::PolicyDocument>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Who may join this tenant as a guest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboundGuestSettings {
    /// Whether the tenant accepts guests at all (partners with `allow: true` excepted).
    #[serde(rename = "allowGuests")]
    pub allow_guests: bool,
    /// When non-empty, only addresses at these domains (or their subdomains) may be invited.
    #[serde(rename = "allowedDomains")]
    pub allowed_domains: Vec<String>,
    /// Addresses at these domains (or their subdomains) are never invited; this wins over every allow.
    #[serde(rename = "blockedDomains")]
    pub blocked_domains: Vec<String>,
    /// Organizations (by the tenant that verified the address's domain) admitted or refused over the defaults.
    #[serde(rename = "partners")]
    pub partners: Vec<crate::guests::CrossTenantPartner>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether this tenant's people may become guests elsewhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboundGuestSettings {
    /// Whether people whose address is at one of this tenant's verified domains may redeem guest invitations of other
    /// tenants (partners excepted).
    #[serde(rename = "allowGuestInvitations")]
    pub allow_guest_invitations: bool,
    /// Host organizations allowed or refused over the default.
    #[serde(rename = "partners")]
    pub partners: Vec<crate::guests::CrossTenantPartner>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Whether an identity is a guest: it carries the server-owned `guest` marker.
pub fn is_guest(identity: &Value) -> bool {
    identity.get("guest").is_some()
}

/// [`is_guest`] for a typed identity.
pub fn is_guest_identity(identity: &Identity) -> bool {
    identity.guest.is_some()
}

/// The guest keys of a decision: `principal.guest` always, and `principal.guestSponsorId` and
/// `principal.homeTenantId` when set. Only an identity acting in its own tenant can be a guest there; an assumed
/// role never is.
pub fn guest_context(identity: &Identity, own_tenant: bool) -> Map<String, Value> {
    let guest = if own_tenant {
        identity.guest.as_ref()
    } else {
        None
    };
    let mut keys = Map::new();
    keys.insert("principal.guest".into(), Value::Bool(guest.is_some()));
    if let Some(guest) = guest {
        keys.insert(
            "principal.guestSponsorId".into(),
            Value::String(guest.sponsor_id.clone()),
        );
        if let Some(home) = &guest.home_tenant_id {
            keys.insert("principal.homeTenantId".into(), Value::String(home.clone()));
        }
    }
    keys
}

/// The settings a tenant has without stored ones.
pub fn default_guest_settings() -> GuestSettings {
    GuestSettings {
        inbound: InboundGuestSettings {
            allow_guests: true,
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            partners: Vec::new(),
            extra: Map::new(),
        },
        outbound: OutboundGuestSettings {
            allow_guest_invitations: true,
            partners: Vec::new(),
            extra: Map::new(),
        },
        access_days: limits::ACCESS_DAYS,
        review_every_days: limits::REVIEW_EVERY_DAYS,
        guest_boundary: None,
        extra: Map::new(),
    }
}

/// [`default_guest_settings`] as the JSON object TypeScript builds.
fn default_guest_settings_value() -> Map<String, Value> {
    let Value::Object(map) = json!({
        "inbound": { "allowGuests": true, "allowedDomains": [], "blockedDomains": [], "partners": [] },
        "outbound": { "allowGuestInvitations": true, "partners": [] },
        "accessDays": 90,
        "reviewEveryDays": 90,
    }) else {
        unreachable!("an object literal")
    };
    map
}

/// A tenant's stored settings record, if it saved any (raw, for read-modify-write).
pub async fn read_guest_settings_record(tx: &Store, tenant_id: &str) -> IamResult<Option<Record>> {
    let stored = tx.get(SETTINGS, tenant_id).await?;
    Ok(stored.filter(|stored| member_str(stored, "tenantId") == Some(tenant_id)))
}

/// A tenant's stored settings, if it saved any.
pub async fn read_guest_settings(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<crate::guests::CrossTenantAccess>> {
    match read_guest_settings_record(tx, tenant_id).await? {
        Some(stored) => Ok(Some(decode(stored)?)),
        None => Ok(None),
    }
}

/// A tenant's settings: the stored ones, or the defaults.
pub async fn guest_settings(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<crate::guests::GuestSettings> {
    let Some(stored) = read_guest_settings(tx, tenant_id).await? else {
        return Ok(default_guest_settings());
    };
    Ok(GuestSettings {
        inbound: stored.inbound,
        outbound: stored.outbound,
        access_days: stored.access_days,
        review_every_days: stored.review_every_days,
        guest_boundary: stored.guest_boundary,
        extra: Map::new(),
    })
}

/// [`guest_settings`] as the JSON object TypeScript builds from a stored record (`stored`) or the defaults: the
/// stored members as they are kept, so the views and `configure` carry them unchanged.
pub fn guest_settings_value(stored: Option<&Record>) -> Map<String, Value> {
    let Some(stored) = stored else {
        return default_guest_settings_value();
    };
    let mut settings = Map::new();
    for key in ["inbound", "outbound", "accessDays", "reviewEveryDays"] {
        if let Some(value) = stored.get(key) {
            settings.insert(key.into(), value.clone());
        }
    }
    if crate::js::truthy(stored.get("guestBoundary")) {
        settings.insert("guestBoundary".into(), stored["guestBoundary"].clone());
    }
    settings
}

/// The ceiling a tenant sets on every guest's decisions, if any (decisions.ts reads it for guests only).
pub async fn guest_boundary(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<better_iam_core::PolicyDocument>> {
    Ok(read_guest_settings(tx, tenant_id)
        .await?
        .and_then(|settings| settings.guest_boundary))
}

/// `domainToASCII(input)` of `node:url`: the WHATWG URL hostname setter on a special URL (UTS #46 mapping, punycode,
/// lowercase), or `''` when the input is not a host.
fn domain_to_ascii(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let Ok(mut url) = url::Url::parse("ws://x") else {
        return String::new();
    };
    if url::quirks::set_hostname(&mut url, input).is_err() {
        return String::new();
    }
    url::quirks::hostname(&url).to_owned()
}

/// An address's domain spelled as verified domains and the domain lists are (domains.ts `domainName`): lowercase
/// ASCII, an internationalized name in its punycode form (UTS #46 mapping, as mail transports convert it), without a
/// trailing dot. INVALID_INPUT for a domain that is not a DNS name.
pub fn email_domain(address: &str) -> IamResult<String> {
    let start = address.rfind('@').map_or(0, |at| at + 1);
    let ascii = domain_to_ascii(&address[start..]);
    domain_name(Some(&Value::String(ascii))).map_err(|_| {
        IamError::new(
            "INVALID_INPUT",
            "Invalid email: its domain is not a DNS name",
        )
    })
}

/// An invited address: a valid email whose domain is spelled as `emailDomain` spells it.
pub fn guest_address(value: Option<&Value>) -> IamResult<String> {
    let address = email(value)?;
    let local = address.rfind('@').map_or(0, |at| at + 1);
    Ok(format!("{}{}", &address[..local], email_domain(&address)?))
}

/// Where an address comes from: its domain, and the tenant that verified that domain (`domainOwners`) unless that
/// is the host itself or a deleted tenant. An address at one of the host's own verified domains belongs to a
/// member, so it is refused (GUEST_NOT_ALLOWED): invite the person as a member instead.
pub async fn guest_origin(
    tx: &Store,
    host_tenant_id: &str,
    address: &str,
) -> IamResult<GuestOrigin> {
    let domain = email_domain(address)?;
    let Some(owner) = tx.get("domainOwners", &domain).await? else {
        return Ok(GuestOrigin {
            domain,
            home_tenant_id: None,
        });
    };
    let owner_tenant = crate::js::js_string(owner.get("tenantId"));
    if owner.get("tenantId").and_then(Value::as_str) == Some(host_tenant_id) {
        return Err(IamError::with_status(
            "GUEST_NOT_ALLOWED",
            format!(
                "{domain} is a verified domain of this organization: invite the person as a member"
            ),
            403,
        ));
    }
    let home = tx.get("tenants", &owner_tenant).await?;
    let home_tenant_id = home
        .filter(|home| member_str(home, "status") != Some("deleted"))
        .map(|home| crate::js::js_string(home.get("id")));
    Ok(GuestOrigin {
        domain,
        home_tenant_id,
    })
}

/// Whether a domain is one of `entries` or a subdomain of one.
pub fn domain_listed(domain: &str, entries: &[String]) -> bool {
    entries
        .iter()
        .any(|entry| domain == entry || domain.ends_with(&format!(".{entry}")))
}

/// Why the host's inbound settings refuse a guest from `origin`, or None when they admit them. A refusal wins (a
/// partner entry with `allow: false`, a blocked domain); a partner entry with `allow: true` then admits the guest
/// over the defaults (`allowGuests`, `allowedDomains`).
pub fn inbound_refusal(settings: &GuestSettings, origin: &GuestOrigin) -> Option<String> {
    let partner = origin.home_tenant_id.as_ref().and_then(|home| {
        settings
            .inbound
            .partners
            .iter()
            .find(|entry| &entry.tenant_id == home)
    });
    if partner.is_some_and(|partner| !partner.allow) {
        return Some(
            "This organization does not accept guests from the person\u{2019}s organization".into(),
        );
    }
    if domain_listed(&origin.domain, &settings.inbound.blocked_domains) {
        return Some(format!(
            "This organization does not accept guests from {}",
            origin.domain
        ));
    }
    if partner.is_some_and(|partner| partner.allow) {
        return None;
    }
    if !settings.inbound.allow_guests {
        return Some("This organization does not accept guests".into());
    }
    if !settings.inbound.allowed_domains.is_empty()
        && !domain_listed(&origin.domain, &settings.inbound.allowed_domains)
    {
        return Some("This organization accepts guests only from its allowed domains".into());
    }
    None
}

/// Whether a home tenant's outbound settings let its people become guests of `hostTenantId`.
pub fn outbound_allows(settings: &GuestSettings, host_tenant_id: &str) -> bool {
    match settings
        .outbound
        .partners
        .iter()
        .find(|entry| entry.tenant_id == host_tenant_id)
    {
        Some(partner) => partner.allow,
        None => settings.outbound.allow_guest_invitations,
    }
}

/// Refuses (GUEST_NOT_ALLOWED, 403) a guest the host's inbound settings or the home tenant's outbound settings do
/// not admit. The outbound refusal says only that the person's organization does not allow it, never what it
/// configured.
pub async fn assert_guest_admitted(
    tx: &Store,
    host: &crate::guests::GuestSettings,
    host_tenant_id: &str,
    origin: &GuestOrigin,
) -> IamResult<()> {
    if let Some(refusal) = inbound_refusal(host, origin) {
        return Err(IamError::with_status("GUEST_NOT_ALLOWED", refusal, 403));
    }
    if let Some(home) = origin
        .home_tenant_id
        .as_deref()
        .filter(|home| !home.is_empty())
        && !outbound_allows(&guest_settings(tx, home).await?, host_tenant_id)
    {
        return Err(IamError::with_status(
            "GUEST_NOT_ALLOWED",
            "The person\u{2019}s organization does not allow its members to join this organization as guests",
            403,
        ));
    }
    Ok(())
}

/// Whether an identity can sponsor guests of `tenantId` now: an active, unexpired person of it who is no guest.
pub fn can_sponsor(
    ctx: &Arc<ServerContext>,
    identity: Option<&better_iam_core::Identity>,
    tenant_id: &str,
) -> bool {
    identity.is_some_and(|identity| {
        identity.tenant_id == tenant_id
            && identity.kind == IdentityKind::User
            && identity.status == IdentityStatus::Active
            && !ctx.identity_expired(identity)
            && !is_guest_identity(identity)
    })
}

/// A guest's sponsor by id; refuses (INVALID_SPONSOR) anyone `canSponsor` does not accept.
pub async fn guest_sponsor(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    sponsor_id: Option<&Value>,
) -> IamResult<better_iam_core::Identity> {
    let sponsor_id = text(sponsor_id, "sponsorId", 256)?;
    let sponsor: Option<Identity> = match tx.get("identities", &sponsor_id).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    match sponsor {
        Some(sponsor) if can_sponsor(ctx, Some(&sponsor), tenant_id) => Ok(sponsor),
        _ => Err(IamError::new(
            "INVALID_SPONSOR",
            "A guest\u{2019}s sponsor must be an active member of the organization who is not a guest",
        )),
    }
}

/// `{ ...value }` of a member value: an object's own members, nothing for anything else.
fn spread_object(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

/// Moves a guest to a new sponsor: the identity's marker and the account, clearing a missing-sponsor flag. Answers
/// the stored account and identity records.
pub async fn set_guest_sponsor(
    tx: &Store,
    account: &Record,
    guest: &Record,
    sponsor_id: &str,
) -> IamResult<(Record, Record)> {
    let identity = if crate::js::truthy(guest.get("guest")) {
        let mut marker = spread_object(guest.get("guest"));
        marker.insert("sponsorId".into(), Value::String(sponsor_id.to_owned()));
        let mut next = guest.clone();
        next.insert("guest".into(), Value::Object(marker));
        tx.put("identities", &next).await?
    } else {
        guest.clone()
    };
    let mut rest = account.clone();
    rest.shift_remove("sponsorMissing");
    rest.shift_remove("sponsorMissingNotifiedAt");
    rest.insert("sponsorId".into(), Value::String(sponsor_id.to_owned()));
    Ok((tx.put(ACCOUNTS, &rest).await?, identity))
}

/// The pending guest invitations a person sent or sponsors are revoked when they are disabled or leave (called by
/// `revokeInvitationsBy` in api/identities.ts). Redemption would refuse them anyway; this keeps the list truthful.
pub async fn revoke_guest_invitations_by(tx: &Store, identity_id: &str) -> IamResult<()> {
    let mut found: indexmap::IndexMap<String, Record> = indexmap::IndexMap::new();
    for field in ["invitedBy", "sponsorId"] {
        for invitation in tx
            .find(
                INVITATIONS,
                &Filter::new().eq(field, identity_id).eq("status", "pending"),
                &find_all(),
            )
            .await?
        {
            found.insert(crate::js::js_string(invitation.get("id")), invitation);
        }
    }
    for invitation in found.into_values() {
        let reason = if member_str(&invitation, "invitedBy") == Some(identity_id) {
            "inviter-inactive"
        } else {
            "sponsor-inactive"
        };
        let mut rest = invitation;
        rest.shift_remove("uniqueKey");
        rest.insert("status".into(), Value::String("revoked".into()));
        rest.insert("revokedReason".into(), Value::String(reason.into()));
        tx.put(INVITATIONS, &rest).await?;
    }
    Ok(())
}

/// Offboarding (identities.offboard): a leaver who is a guest has their guest account closed as `removed`, and the
/// guests the leaver sponsors move to `successor` when that person can sponsor (each audited as
/// `guest:sponsor-change`); otherwise they are flagged `sponsorMissing` so the owners assign someone.
pub async fn hand_over_guests(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    leaver: &better_iam_core::Identity,
    successor: Option<&better_iam_core::Identity>,
) -> IamResult<Value> {
    let mut reassigned = 0.0;
    let mut unsponsored = 0.0;
    if let Some(mut own) = tx.get(ACCOUNTS, &leaver.id).await?
        && member_str(&own, "tenantId") == Some(leaver.tenant_id.as_str())
        && member_str(&own, "status") == Some("active")
    {
        own.insert("status".into(), Value::String("removed".into()));
        own.insert("endedAt".into(), crate::js::number(ctx.now()));
        own.insert(
            "endedBy".into(),
            Value::String(principal.identity.id.clone()),
        );
        own.insert("removalReason".into(), Value::String("Offboarded".into()));
        tx.put(ACCOUNTS, &own).await?;
    }
    let heir = successor.filter(|successor| {
        successor.id != leaver.id && can_sponsor(ctx, Some(successor), &leaver.tenant_id)
    });
    for account in tx
        .find(
            ACCOUNTS,
            &Filter::new()
                .eq("tenantId", leaver.tenant_id.clone())
                .eq("sponsorId", leaver.id.clone())
                .eq("status", "active"),
            &find_all(),
        )
        .await?
    {
        let identity_id = crate::js::js_string(account.get("identityId"));
        let Some(guest) = tx.get("identities", &identity_id).await? else {
            continue;
        };
        if member_str(&guest, "status") == Some("deleted") {
            continue;
        }
        let guest_id = crate::js::js_string(guest.get("id"));
        if let Some(heir) = heir
            && heir.id != guest_id
        {
            set_guest_sponsor(tx, &account, &guest, &heir.id).await?;
            let mut metadata = Map::new();
            metadata.insert("from".into(), Value::String(leaver.id.clone()));
            metadata.insert("to".into(), Value::String(heir.id.clone()));
            metadata.insert("reason".into(), Value::String("offboarding".into()));
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "guest:sponsor-change",
                    &leaver.tenant_id,
                    &guest_id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
            reassigned += 1.0;
            continue;
        }
        flag_sponsor_missing(ctx, tx, principal, &account, "offboarding").await?;
        unsponsored += 1.0;
    }
    Ok(json!({
        "reassigned": crate::js::number(reassigned),
        "unsponsored": crate::js::number(unsponsored),
    }))
}

/// Identity deletion (identities.ts `deleteIdentity`): a deleted guest's account row goes (the audit trail keeps
/// its history), and the guests the person sponsored are flagged `sponsorMissing`.
pub async fn release_guest_records(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    identity: &Value,
) -> IamResult<()> {
    let identity_id = crate::js::js_string(identity.get("id"));
    let tenant_id = identity.get("tenantId").cloned().unwrap_or(Value::Null);
    if let Some(own) = tx.get(ACCOUNTS, &identity_id).await?
        && own.get("tenantId") == Some(&tenant_id)
    {
        tx.delete(ACCOUNTS, &crate::js::js_string(own.get("id")))
            .await?;
    }
    for account in tx
        .find(
            ACCOUNTS,
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("sponsorId", identity_id.clone())
                .eq("status", "active"),
            &find_all(),
        )
        .await?
    {
        flag_sponsor_missing(ctx, tx, principal, &account, "deletion").await?;
    }
    Ok(())
}

/// Flags a guest whose sponsor is leaving, audited as `guest:sponsor-missing` (the worker emails the owners).
async fn flag_sponsor_missing(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    account: &Record,
    reason: &str,
) -> IamResult<()> {
    if crate::js::truthy(account.get("sponsorMissing")) {
        return Ok(());
    }
    let mut flagged = account.clone();
    flagged.insert("sponsorMissing".into(), Value::Bool(true));
    tx.put(ACCOUNTS, &flagged).await?;
    let mut metadata = Map::new();
    if let Some(sponsor_id) = account.get("sponsorId") {
        metadata.insert("sponsorId".into(), sponsor_id.clone());
    }
    metadata.insert("reason".into(), Value::String(reason.into()));
    ctx.events()?
        .audit(
            tx,
            principal,
            "guest:sponsor-missing",
            &crate::js::js_string(account.get("tenantId")),
            &crate::js::js_string(account.get("identityId")),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await
}
