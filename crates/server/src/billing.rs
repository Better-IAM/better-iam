//! Port of `packages/server/src/billing.ts`.
//!
//! Billing and spend tracking. Meters name what is billed (API calls, seat-days, GB-days, AI inference); a rate card
//! prices them; usage events record how much each tenant, person, agent, team and department used. Spend is computed
//! per billing account (the nearest tenant with a billing profile, else the organization) and period (a calendar month
//! in the billing time zone): each meter's period total is priced once with its tiers, then allocated back to the usage
//! that produced it by share of quantity (a blended rate), so individual, team, department and project spend always add
//! up to the account's charges. Meters with `pricing: 'reported'` carry their cost on each event instead (inference).

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, Identity, IdentityKind, IdentityStatus, Record,
    Tenant, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::context::{ServerContext, Store};
use crate::js::{ThrownError, number};
use crate::port::{decode, encode};
use crate::validation::{integer, object, text};

/// A spend budget: an amount per month, quarter or year for a tenant subtree, a team, a department or a person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingBudget {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "subjectType")]
    pub subject_type: crate::billing::BudgetSubjectType,
    /// The tenant (in the budget's subtree), team, department or identity.
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    #[serde(rename = "period")]
    pub period: crate::billing::BudgetPeriodKind,
    /// Only these meter keys count (all when absent).
    #[serde(rename = "meters", default, skip_serializing_if = "Option::is_none")]
    pub meters: Option<Vec<String>>,
    /// Percentages of the amount that trigger an alert, once per window each (default 50, 80, 100).
    #[serde(rename = "thresholds")]
    pub thresholds: Vec<f64>,
    /// Also alert when the linear month-end (or quarter-end, year-end) projection passes 100%.
    #[serde(rename = "forecastAlerts")]
    pub forecast_alerts: bool,
    /// Who is told: the tenant's owners, the subject (the person, team maintainers, department heads), extra emails.
    #[serde(rename = "notify")]
    pub notify: Value,
    /// Refuse usage covered by the budget once it is spent (`record` with `enforceBudgets`, `billing.check`).
    #[serde(rename = "enforce")]
    pub enforce: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Marks a threshold as alerted in a budget window (uniqueKey `{budgetId}:{windowStart}:{kind}:{threshold}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingBudgetAlert {
    /// Empty for anomaly markers (uniqueKey `anomaly:{dimension}:{key}:{day}`).
    #[serde(rename = "budgetId")]
    pub budget_id: String,
    #[serde(rename = "window")]
    pub window: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "threshold")]
    pub threshold: f64,
    #[serde(rename = "spentMicros")]
    pub spent_micros: f64,
    #[serde(rename = "alertedAt")]
    pub alerted_at: f64,
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

/// A promotion: a percentage or an amount off invoices, once, for some months, or for good, like Stripe coupons.
/// The platform defines coupons (uniqueKey `code:{CODE}`); accounts redeem them by code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingCoupon {
    #[serde(rename = "code")]
    pub code: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "percentOff",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub percent_off: Option<f64>,
    #[serde(
        rename = "amountOffMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub amount_off_micros: Option<f64>,
    #[serde(rename = "duration")]
    pub duration: String,
    /// `repeating`: how many monthly invoices it applies to.
    #[serde(
        rename = "durationInMonths",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_in_months: Option<f64>,
    #[serde(
        rename = "maxRedemptions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_redemptions: Option<f64>,
    #[serde(rename = "redemptions")]
    pub redemptions: f64,
    /// Last moment it can be redeemed.
    #[serde(rename = "redeemBy", default, skip_serializing_if = "Option::is_none")]
    pub redeem_by: Option<f64>,
    #[serde(rename = "active")]
    pub active: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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

/// Prepaid or promotional credit a billing account's statements draw on (earliest expiry first).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingCredit {
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    #[serde(rename = "remainingMicros")]
    pub remaining_micros: f64,
    #[serde(rename = "reason")]
    pub reason: String,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "grantedAt")]
    pub granted_at: f64,
    #[serde(rename = "grantedBy")]
    pub granted_by: String,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
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

/// A credit note reduces what a finalized invoice asks for, like Stripe's: first the amount still due; anything
/// beyond (a paid part) becomes account credit or is recorded as refunded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingCreditNote {
    #[serde(rename = "number")]
    pub number: String,
    #[serde(rename = "statementId")]
    pub statement_id: String,
    #[serde(rename = "statementNumber")]
    pub statement_number: String,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    #[serde(rename = "reason")]
    pub reason: crate::billing::CreditNoteReason,
    #[serde(rename = "memo", default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// How the amount was used: against the amount due, as account credit, or refunded outside Better IAM.
    #[serde(rename = "applied")]
    pub applied: Value,
    /// The account credit created for `applied.creditMicros`.
    #[serde(rename = "creditId", default, skip_serializing_if = "Option::is_none")]
    pub credit_id: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "issuedBy")]
    pub issued_by: String,
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

/// A coupon redeemed by a billing account (uniqueKey `coupon:{couponId}`), with how many invoices it has
/// discounted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingDiscount {
    #[serde(rename = "couponId")]
    pub coupon_id: String,
    #[serde(rename = "code")]
    pub code: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "percentOff",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub percent_off: Option<f64>,
    #[serde(
        rename = "amountOffMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub amount_off_micros: Option<f64>,
    #[serde(rename = "duration")]
    pub duration: String,
    #[serde(
        rename = "durationInMonths",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_in_months: Option<f64>,
    /// Monthly invoices discounted so far.
    #[serde(rename = "appliedInvoices")]
    pub applied_invoices: f64,
    #[serde(rename = "redeemedAt")]
    pub redeemed_at: f64,
    #[serde(rename = "redeemedBy")]
    pub redeemed_by: String,
    /// No longer applies (used up or removed).
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<f64>,
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

/// A one-off charge (or, with a negative amount, a credit) for a billing account's next invoice, like Stripe's
/// pending invoice items: `pending` until an invoice for its period (or the next one) is finalized, then
/// `invoiced`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingInvoiceItem {
    // Members in the order TypeScript writes proration items (`prorationItems`).
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(rename = "unitAmountMicros")]
    pub unit_amount_micros: f64,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    /// Bill it on the invoice for this month (default: the next invoice).
    #[serde(rename = "period", default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(
        rename = "statementId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub statement_id: Option<String>,
    /// `proration` items come from subscription changes.
    #[serde(rename = "source")]
    pub source: String,
    #[serde(
        rename = "subscriptionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subscription_id: Option<String>,
    #[serde(rename = "metadata", default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IndexMap<String, String>>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a meter counts, and how its usage becomes cost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingMeter {
    /// Unique along a tenant's ancestry; the tenant nearest the root that defines a key owns it (uniqueKey = key).
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "name")]
    pub name: String,
    /// Unit label such as `request`, `seat-day`, `GB-day` or `token`.
    #[serde(rename = "unit")]
    pub unit: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// `sum` adds quantities; `unique` counts the distinct people or agents with usage in the period (active users).
    #[serde(rename = "aggregation")]
    pub aggregation: String,
    /// `rate-card`: priced from the rate card per period; `reported`: every event carries its own cost.
    #[serde(rename = "pricing")]
    pub pricing: String,
    /// Archived meters refuse new usage but keep their history.
    #[serde(rename = "archived")]
    pub archived: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A plan subscribers pay monthly, like Stripe products with prices or Orb plans: fixed fees, seats, and prices for
/// meters. Defined by a tenant (the platform for organizations) for accounts below it (uniqueKey = key).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingPlan {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "items")]
    pub items: Vec<crate::billing::PlanItem>,
    /// Days a new subscription is free of fee and seat charges.
    #[serde(rename = "trialDays", default, skip_serializing_if = "Option::is_none")]
    pub trial_days: Option<f64>,
    /// Billing managers of an account may subscribe and cancel it themselves.
    #[serde(rename = "selfServe")]
    pub self_serve: bool,
    #[serde(rename = "archived")]
    pub archived: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A rate card entry: the price of a meter for a tenant's subtree from a period on (until a later entry). The
/// meter's defining tenant sets its list price on itself and negotiated prices for tenants below it; the entry
/// nearest to the billing account wins. Stored in the tenant it applies to (uniqueKey `{meterId}:{effectiveFrom}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingPrice {
    #[serde(rename = "meterId")]
    pub meter_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    /// The tenant that defines the meter (and set this price).
    #[serde(rename = "definerId")]
    pub definer_id: String,
    /// First period the price applies to.
    #[serde(rename = "effectiveFrom")]
    pub effective_from: String,
    #[serde(rename = "spec")]
    pub spec: Value,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "setAt")]
    pub set_at: f64,
    #[serde(rename = "setBy")]
    pub set_by: String,
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

/// Who pays: a tenant with a billing profile is a billing account for its subtree (down to tenants with their own
/// profile). Organizations directly below the root are accounts even without a profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingProfile {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(
        rename = "companyName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub company_name: Option<String>,
    /// Statements and spend alerts go here (in addition to owners when empty).
    #[serde(rename = "billingEmails")]
    pub billing_emails: Vec<String>,
    #[serde(rename = "taxId", default, skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(rename = "address", default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(
        rename = "purchaseOrder",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub purchase_order: Option<String>,
    /// Printed on statements; defaults to nothing.
    #[serde(
        rename = "costCenter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_center: Option<String>,
    /// Days after issue a statement is due (overrides `billing.paymentTermsDays`).
    #[serde(
        rename = "paymentTermsDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_terms_days: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A billing profile's details (`billing.getProfile`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingProfileFields {
    #[serde(
        rename = "companyName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub company_name: Option<String>,
    /// Statements and spend alerts go here (in addition to owners when empty).
    #[serde(rename = "billingEmails")]
    pub billing_emails: Vec<String>,
    #[serde(rename = "taxId", default, skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(rename = "address", default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(
        rename = "purchaseOrder",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub purchase_order: Option<String>,
    /// Printed on statements; defaults to nothing.
    #[serde(
        rename = "costCenter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_center: Option<String>,
    /// Days after issue a statement is due (overrides `billing.paymentTermsDays`).
    #[serde(
        rename = "paymentTermsDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_terms_days: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A daily bucket of usage with the same meter and attribution; spend is computed from these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingRollup {
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "day")]
    pub day: String,
    #[serde(rename = "meterId")]
    pub meter_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "teamIds", default)]
    pub team_ids: Vec<String>,
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    #[serde(rename = "tags", default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<IndexMap<String, String>>,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    #[serde(rename = "events")]
    pub events: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingSettings {
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "timeZone")]
    pub time_zone: String,
    #[serde(rename = "usageRetentionDays")]
    pub usage_retention_days: f64,
    #[serde(rename = "teamAttribution")]
    pub team_attribution: String,
    #[serde(rename = "paymentTermsDays")]
    pub payment_terms_days: f64,
    #[serde(rename = "statementPrefix")]
    pub statement_prefix: String,
    #[serde(rename = "issuer", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<crate::billing::InvoiceIssuer>,
    #[serde(rename = "paymentReminderDays")]
    pub payment_reminder_days: Vec<f64>,
    #[serde(rename = "autoFinalize")]
    pub auto_finalize: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An invoice for a billing account (called a statement in earlier releases): the monthly one has uniqueKey
/// `period:{period}` until voided; a new subscription's first invoice `subscription:{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingStatement {
    /// Empty while a draft; assigned when the invoice is finalized.
    #[serde(rename = "number")]
    pub number: String,
    #[serde(rename = "status")]
    pub status: String,
    /// When the invoice was finalized (or, for a draft, drawn up).
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "dueAt")]
    pub due_at: f64,
    /// SHA-256 of the invoice's content (lines, totals, bill-to), for tamper evidence; empty while a draft.
    #[serde(rename = "hash")]
    pub hash: String,
    /// Payments received; the sum is `amountPaidMicros`.
    #[serde(rename = "payments", default, skip_serializing_if = "Option::is_none")]
    pub payments: Option<Vec<crate::billing::InvoicePayment>>,
    #[serde(
        rename = "amountPaidMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub amount_paid_micros: Option<f64>,
    /// Credit notes issued against the invoice (`billing.createCreditNote`).
    #[serde(
        rename = "creditNotesMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credit_notes_micros: Option<f64>,
    /// Pending invoice items the invoice will bill (drafts) or billed (finalized).
    #[serde(
        rename = "invoiceItemIds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub invoice_item_ids: Option<Vec<String>>,
    /// Subscription months the invoice bills in advance (released again if it is voided).
    #[serde(
        rename = "advanceBilled",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub advance_billed: Option<Vec<Value>>,
    /// Account credit created from a negative balance (credit items larger than the charges).
    #[serde(
        rename = "carryForward",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub carry_forward: Option<Value>,
    /// Payment reminders sent, by day relative to the due date (`billing.paymentReminderDays`).
    #[serde(rename = "reminders", default, skip_serializing_if = "Option::is_none")]
    pub reminders: Option<Vec<Value>>,
    #[serde(rename = "paidAt", default, skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<f64>,
    #[serde(rename = "paidBy", default, skip_serializing_if = "Option::is_none")]
    pub paid_by: Option<String>,
    #[serde(
        rename = "paymentReference",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_reference: Option<String>,
    #[serde(rename = "voidedAt", default, skip_serializing_if = "Option::is_none")]
    pub voided_at: Option<f64>,
    #[serde(rename = "voidedBy", default, skip_serializing_if = "Option::is_none")]
    pub voided_by: Option<String>,
    #[serde(
        rename = "voidReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub void_reason: Option<String>,
    #[serde(
        rename = "markedUncollectibleAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub marked_uncollectible_at: Option<f64>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "periodStart")]
    pub period_start: f64,
    #[serde(rename = "periodEnd")]
    pub period_end: f64,
    #[serde(rename = "lines")]
    pub lines: Vec<crate::billing::StatementLine>,
    /// Why the invoice exists: the monthly close (default), a new subscription's first period, or an invoice made by
    /// hand.
    #[serde(
        rename = "billingReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub billing_reason: Option<String>,
    /// The sum of the lines.
    #[serde(rename = "subtotalMicros")]
    pub subtotal_micros: f64,
    /// Coupon discounts (`billing.redeemCoupon`), after the contract discount.
    #[serde(rename = "coupons", default, skip_serializing_if = "Option::is_none")]
    pub coupons: Option<Vec<Value>>,
    /// The account's negotiated discount on usage (`billing.setTerms`).
    #[serde(rename = "discount", default, skip_serializing_if = "Option::is_none")]
    pub discount: Option<Value>,
    /// What the month fell short of the account's minimum monthly commitment, billed on top.
    #[serde(
        rename = "commitment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub commitment: Option<Value>,
    #[serde(rename = "creditsMicros")]
    pub credits_micros: f64,
    #[serde(rename = "creditsApplied")]
    pub credits_applied: Vec<Value>,
    /// Tax on the amount due after discount, commitment and credit.
    #[serde(rename = "tax", default, skip_serializing_if = "Option::is_none")]
    pub tax: Option<Value>,
    #[serde(rename = "totalMicros")]
    pub total_micros: f64,
    /// Where the billable spend came from (largest first; teams, departments and people capped at 50).
    #[serde(rename = "breakdown")]
    pub breakdown: Value,
    #[serde(rename = "billTo")]
    pub bill_to: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A billing account's subscription to a plan (uniqueKey `plan:{planId}` while it lasts). Seats change over time,
/// so `seatHistory` keeps every change for prorated charges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingSubscription {
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "planKey")]
    pub plan_key: String,
    #[serde(rename = "planName")]
    pub plan_name: String,
    #[serde(rename = "startedAt")]
    pub started_at: f64,
    #[serde(
        rename = "trialEndsAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trial_ends_at: Option<f64>,
    /// Set when the subscription ends (at a period end for `cancelAtPeriodEnd`).
    #[serde(rename = "endsAt", default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<f64>,
    #[serde(rename = "cancelAtPeriodEnd")]
    pub cancel_at_period_end: bool,
    #[serde(
        rename = "canceledAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub canceled_at: Option<f64>,
    #[serde(
        rename = "canceledBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub canceled_by: Option<String>,
    #[serde(rename = "seats")]
    pub seats: f64,
    /// Seat counts from each change on, oldest first.
    #[serde(rename = "seatHistory")]
    pub seat_history: Vec<Value>,
    /// Advance-billed months already invoiced (`YYYY-MM`).
    #[serde(rename = "billedAdvance")]
    pub billed_advance: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

/// Commercial terms of a billing account, which only root administrators set (`billing.setTerms`): a discount on
/// usage, a minimum monthly commitment, and the tax statements add (uniqueKey `terms`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingTerms {
    /// Percent off usage at rate-card prices, 0 to 100.
    #[serde(
        rename = "discountPercent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub discount_percent: Option<f64>,
    /// Least a month is billed, in micros; a shortfall is billed as a true-up.
    #[serde(
        rename = "minimumCommitmentMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_commitment_micros: Option<f64>,
    /// Tax added to the amount due, 0 to 100 percent.
    #[serde(
        rename = "taxRatePercent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tax_rate_percent: Option<f64>,
    /// How the tax line reads, such as `VAT` (default `Tax`).
    #[serde(rename = "taxLabel", default, skip_serializing_if = "Option::is_none")]
    pub tax_label: Option<String>,
    #[serde(rename = "setAt")]
    pub set_at: f64,
    #[serde(rename = "setBy")]
    pub set_by: String,
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

/// One usage event (kept `usageRetentionDays` after its period ends).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingUsageRecord {
    #[serde(rename = "meterId")]
    pub meter_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    /// Reported meters: the event's cost in micros.
    #[serde(
        rename = "costMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_micros: Option<f64>,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// The person's direct teams when the usage was recorded (or the team the caller named).
    #[serde(rename = "teamIds")]
    pub team_ids: Vec<String>,
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    #[serde(rename = "tags", default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<IndexMap<String, String>>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: f64,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "day")]
    pub day: String,
    #[serde(rename = "recordedAt")]
    pub recorded_at: f64,
    /// The identity that recorded it, or `deployment` for trusted server code.
    #[serde(rename = "recordedBy")]
    pub recorded_by: String,
    #[serde(rename = "sourceId", default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(rename = "rollupId")]
    pub rollup_id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
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

/// A budget window kind as JSON: `'month' | 'quarter' | 'year'`.
pub type BudgetPeriodKind = Value;

/// A budget subject kind as JSON: `'tenant' | 'team' | 'department' | 'identity'`.
pub type BudgetSubjectType = Value;

/// Usage with its share of cost: a daily roll-up after pricing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargedRow {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "day")]
    pub day: String,
    #[serde(rename = "meterId")]
    pub meter_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "teamIds")]
    pub team_ids: Vec<String>,
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    #[serde(rename = "tags", default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<IndexMap<String, String>>,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    #[serde(rename = "events")]
    pub events: f64,
    /// Chargeback only: the meter is defined inside the billing account (never on a statement).
    #[serde(rename = "internal")]
    pub internal: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A credit note reason as JSON (Stripe's list): `'duplicate' | 'fraudulent' | 'order_change' |
/// 'product_unsatisfactory' | 'other'`.
pub type CreditNoteReason = Value;

/// Team and department trees of the tenants in scope, for roll-ups and labels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Directory {
    #[serde(rename = "teams")]
    pub teams: IndexMap<String, crate::teams::Team>,
    #[serde(rename = "departments")]
    pub departments: IndexMap<String, crate::departments::Department>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Who issues invoices: printed at the top of every invoice (`billing.issuer`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoiceIssuer {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "address", default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "taxId", default, skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(rename = "email", default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "url", default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How to pay: bank details, a payment link, terms (printed under the totals).
    #[serde(
        rename = "paymentInstructions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_instructions: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A payment received against an invoice (`billing.recordPayment`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvoicePayment {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    /// How it was paid: `card`, `bank_transfer`, `check`, `manual`, ... (free text, 32 characters).
    #[serde(rename = "method")]
    pub method: String,
    #[serde(rename = "reference", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: f64,
    #[serde(rename = "recordedBy")]
    pub recorded_by: String,
    /// What the payment exceeded the amount due by, kept as account credit (`creditId`).
    #[serde(
        rename = "overpaymentMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub overpayment_micros: Option<f64>,
    #[serde(rename = "creditId", default, skip_serializing_if = "Option::is_none")]
    pub credit_id: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A meter's charge for an account and period. A meter used both while a subscription's plan priced it and outside
/// that time has one charge per price (the plan's, the rate card's).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeterCharge {
    #[serde(rename = "meterId")]
    pub meter_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "unit")]
    pub unit: String,
    /// The tenant that defines the meter.
    #[serde(rename = "definedBy")]
    pub defined_by: String,
    #[serde(rename = "internal")]
    pub internal: bool,
    #[serde(rename = "aggregation")]
    pub aggregation: String,
    #[serde(rename = "pricing")]
    pub pricing: String,
    /// Summed quantity, or distinct people and agents for `unique` meters.
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    #[serde(rename = "price", default, skip_serializing_if = "Option::is_none")]
    pub price: Option<Value>,
    /// A rate-card meter without a price for the account: its usage costs nothing.
    #[serde(rename = "unpriced", default, skip_serializing_if = "Option::is_none")]
    pub unpriced: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One item of a plan: a recurring fee, a per-seat fee, or the plan's price for a meter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanItem {
    /// Stable within the plan (1-64 lowercase letters, digits, `-`, `_`).
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "name")]
    pub name: String,
    /// `fee`: the monthly amount.
    #[serde(
        rename = "amountMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub amount_micros: Option<f64>,
    /// `seat`: the monthly amount per seat.
    #[serde(
        rename = "unitAmountMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_amount_micros: Option<f64>,
    /// Stored in the order TypeScript writes items (`billing` before `includedSeats`).
    /// `fee` and `seat`: charged at the start of each month for that month (default) or at its end.
    #[serde(rename = "billing", default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<String>,
    /// `seat`: seats included in the plan before any is charged.
    #[serde(
        rename = "includedSeats",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub included_seats: Option<f64>,
    /// `usage`: the meter key and the price subscribers pay for it instead of the rate card.
    #[serde(rename = "meter", default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    #[serde(rename = "price", default, skip_serializing_if = "Option::is_none")]
    pub price: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Caches account computations within one call (spend for several periods, budgets sharing accounts): account spend
/// by `{accountId}:{period}` (`Map<string, Promise<AccountSpend>>`; a failed computation stays failed). Clones share
/// the entries.
#[derive(Clone, Default)]
pub struct SpendCache {
    entries: Arc<Mutex<IndexMap<String, IamResult<AccountSpend>>>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementAllocation {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a statement bills: its period, lines, credits, totals, breakdown and bill-to details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementBody {
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "currency")]
    pub currency: String,
    #[serde(rename = "periodStart")]
    pub period_start: f64,
    #[serde(rename = "periodEnd")]
    pub period_end: f64,
    #[serde(rename = "lines")]
    pub lines: Vec<crate::billing::StatementLine>,
    /// Why the invoice exists: the monthly close (default), a new subscription's first period, or an invoice made by
    /// hand.
    #[serde(
        rename = "billingReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub billing_reason: Option<String>,
    /// The sum of the lines.
    #[serde(rename = "subtotalMicros")]
    pub subtotal_micros: f64,
    /// Coupon discounts (`billing.redeemCoupon`), after the contract discount.
    #[serde(rename = "coupons", default, skip_serializing_if = "Option::is_none")]
    pub coupons: Option<Vec<Value>>,
    /// The account's negotiated discount on usage (`billing.setTerms`).
    #[serde(rename = "discount", default, skip_serializing_if = "Option::is_none")]
    pub discount: Option<Value>,
    /// What the month fell short of the account's minimum monthly commitment, billed on top.
    #[serde(
        rename = "commitment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub commitment: Option<Value>,
    #[serde(rename = "creditsMicros")]
    pub credits_micros: f64,
    #[serde(rename = "creditsApplied")]
    pub credits_applied: Vec<Value>,
    /// Tax on the amount due after discount, commitment and credit.
    #[serde(rename = "tax", default, skip_serializing_if = "Option::is_none")]
    pub tax: Option<Value>,
    #[serde(rename = "totalMicros")]
    pub total_micros: f64,
    /// Where the billable spend came from (largest first; teams, departments and people capped at 50).
    #[serde(rename = "breakdown")]
    pub breakdown: Value,
    #[serde(rename = "billTo")]
    pub bill_to: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One invoice line. Usage lines (`kind` absent or `usage`) name a meter; `fee` and `seat` lines come from
/// subscriptions (with the service period they cover and the share of it billed); `item` lines are one-off invoice
/// items.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementLine {
    #[serde(rename = "kind", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Usage lines: the meter key.
    #[serde(rename = "meter", default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "unit")]
    pub unit: String,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    /// Price of one unit, for fee, seat and item lines and single-tier usage.
    #[serde(
        rename = "unitAmountMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_amount_micros: Option<f64>,
    #[serde(rename = "amountMicros")]
    pub amount_micros: f64,
    /// Usage lines: how the meter is priced.
    #[serde(rename = "pricing", default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<String>,
    #[serde(rename = "price", default, skip_serializing_if = "Option::is_none")]
    pub price: Option<Value>,
    #[serde(rename = "unpriced", default, skip_serializing_if = "Option::is_none")]
    pub unpriced: Option<bool>,
    /// Tiers the quantity used (graduated and volume prices).
    #[serde(rename = "tiers", default, skip_serializing_if = "Option::is_none")]
    pub tiers: Option<Vec<Value>>,
    /// Free units taken off before pricing.
    #[serde(
        rename = "includedQuantity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub included_quantity: Option<f64>,
    /// The price's minimum or maximum changed the amount; this is what the tiers came to.
    #[serde(
        rename = "adjustedFromMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub adjusted_from_micros: Option<f64>,
    /// Fee and seat lines: the time they pay for.
    #[serde(
        rename = "servicePeriod",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_period: Option<Value>,
    /// Share of the service period billed (0-1) when a subscription started, ended or changed within it.
    #[serde(rename = "proration", default, skip_serializing_if = "Option::is_none")]
    pub proration: Option<f64>,
    #[serde(
        rename = "subscriptionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subscription_id: Option<String>,
    #[serde(
        rename = "planItemId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub plan_item_id: Option<String>,
    #[serde(
        rename = "invoiceItemId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub invoice_item_id: Option<String>,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What `record` needs: where, what and how much, and who to attribute it to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageInput {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    /// Default 1.
    #[serde(rename = "quantity", default, skip_serializing_if = "Option::is_none")]
    pub quantity: Option<f64>,
    /// Reported meters only: the event's cost in currency units.
    #[serde(rename = "cost", default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
    /// The person, service account or agent that used it (an identity of the tenant or an ancestor).
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    /// Attribute to this team instead of the person's own teams.
    #[serde(rename = "teamId", default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Up to 10 labels (`project`, `environment`, `feature`) reports can group by.
    #[serde(rename = "tags", default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<IndexMap<String, String>>,
    /// When it happened (default now); at most five minutes ahead, and never in a period already invoiced.
    #[serde(
        rename = "occurredAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub occurred_at: Option<f64>,
    /// Makes retries safe: a repeated key returns the first receipt and records nothing.
    #[serde(
        rename = "idempotencyKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotency_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageReceipt {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "meter")]
    pub meter: String,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(
        rename = "costMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_micros: Option<f64>,
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: f64,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "teamIds")]
    pub team_ids: Vec<String>,
    #[serde(
        rename = "departmentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub department_id: Option<String>,
    /// True when the idempotency key had already been used.
    #[serde(rename = "duplicate")]
    pub duplicate: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------------------------------------------------------------------------------------------------------------
// Collections, terms and settings

/// `billingCollections.meters`.
pub const METERS: &str = "billingMeters";
/// `billingCollections.prices`.
pub const PRICES: &str = "billingPrices";
/// `billingCollections.usage`.
pub const USAGE: &str = "billingUsage";
/// `billingCollections.rollups`.
pub const ROLLUPS: &str = "billingRollups";
/// `billingCollections.budgets`.
pub const BUDGETS: &str = "billingBudgets";
/// `billingCollections.budgetAlerts`.
pub const BUDGET_ALERTS: &str = "billingBudgetAlerts";
/// `billingCollections.credits`.
pub const CREDITS: &str = "billingCredits";
/// `billingCollections.profiles`.
pub const PROFILES: &str = "billingProfiles";
/// `billingCollections.statements`.
pub const STATEMENTS: &str = "billingStatements";
/// `billingCollections.terms`.
pub const TERMS: &str = "billingTerms";
/// `billingCollections.invoiceItems`.
pub const INVOICE_ITEMS: &str = "billingInvoiceItems";
/// `billingCollections.creditNotes`.
pub const CREDIT_NOTES: &str = "billingCreditNotes";
/// `billingCollections.plans`.
pub const PLANS: &str = "billingPlans";
/// `billingCollections.subscriptions`.
pub const SUBSCRIPTIONS: &str = "billingSubscriptions";
/// `billingCollections.coupons`.
pub const COUPONS: &str = "billingCoupons";
/// `billingCollections.discounts`.
pub const DISCOUNTS: &str = "billingDiscounts";

/// `tx.find(collection, filter)` with the store's default order.
async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `tx.find<T>(collection, filter)` decoded.
async fn find_typed<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<T>> {
    find_records(tx, collection, filter)
        .await?
        .into_iter()
        .map(decode)
        .collect()
}

/// `tx.get<T>(collection, id)` decoded.
async fn get_typed<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    id: &str,
) -> IamResult<Option<T>> {
    match tx.get(collection, id).await? {
        Some(record) => decode(record).map(Some),
        None => Ok(None),
    }
}

/// The contract terms of a billing account, if the platform set any.
pub async fn terms_of(
    tx: &Store,
    account_id: &str,
) -> IamResult<Option<crate::billing::BillingTerms>> {
    Ok(find_typed(
        tx,
        TERMS,
        Filter::new()
            .eq("tenantId", account_id)
            .eq("uniqueKey", "terms"),
    )
    .await?
    .into_iter()
    .next())
}

/// The contract terms a billing account's invoices use: its own, else the discount and tax of the nearest ancestor
/// with terms, so a sub-account carved out of an organization stays under the organization's contract. A minimum
/// commitment is not inherited (each sub-account would owe it again): it stays with the account it was set on,
/// which is invoiced for it even in a month without usage.
pub async fn account_terms_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &better_iam_core::Tenant,
) -> IamResult<Option<crate::billing::BillingTerms>> {
    for (index, realm) in ctx.ancestry(tx, account).await?.iter().enumerate() {
        let Some(mut terms) = terms_of(tx, &realm.id).await? else {
            continue;
        };
        if index == 0 {
            return Ok(Some(terms));
        }
        terms.minimum_commitment_micros = None;
        return Ok(Some(terms));
    }
    Ok(None)
}

/// `fail(message)` of `billingSettings`.
fn settings_failure(message: &str) -> IamError {
    IamError::new("INVALID_CONFIG", format!("billing.{message}"))
}

/// `regex.test(value)` converts its argument to a string first.
fn js_text(value: &Value) -> String {
    crate::js::js_string(Some(value))
}

/// Validates the `billing` option; a bad value fails construction with INVALID_CONFIG.
pub fn billing_settings(options: Option<&Value>) -> IamResult<crate::billing::BillingSettings> {
    let option = |key: &str| crate::js::defined(crate::js::member(options, key)).cloned();
    let currency = option("currency").unwrap_or_else(|| json!("USD"));
    let time_zone = option("timeZone").unwrap_or_else(|| json!("UTC"));
    let usage_retention_days = option("usageRetentionDays").unwrap_or_else(|| json!(400));
    let team_attribution = option("teamAttribution").unwrap_or_else(|| json!("split"));
    let payment_terms_days = option("paymentTermsDays").unwrap_or_else(|| json!(30));
    let statement_prefix = option("statementPrefix").unwrap_or_else(|| json!("INV"));
    let payment_reminder_days =
        option("paymentReminderDays").unwrap_or_else(|| json!([-3, 0, 7, 14]));
    let auto_finalize = option("autoFinalize").unwrap_or(Value::Bool(true));
    let Value::Bool(auto_finalize) = auto_finalize else {
        return Err(settings_failure("autoFinalize must be a boolean"));
    };
    let mut issuer_setting: Option<crate::billing::InvoiceIssuer> = None;
    if let Some(raw) = crate::js::member(options, "issuer") {
        let issuer = match raw {
            Value::Object(map) if !crate::js::is_function(Some(raw)) => Some(map),
            // Arrays are objects to `typeof`; every member then reads as undefined.
            Value::Array(_) => None,
            _ => return Err(settings_failure("issuer must be an object")),
        };
        let field = |key: &str, max: usize, required: bool| -> IamResult<()> {
            let value = issuer.and_then(|map| map.get(key));
            if value.is_none() && !required {
                return Ok(());
            }
            match value {
                Some(Value::String(text))
                    if !core_js::trim(text).is_empty() && core_js::utf16_len(text) <= max =>
                {
                    Ok(())
                }
                _ => Err(settings_failure(&format!(
                    "issuer.{key} must be text of 1-{max} characters"
                ))),
            }
        };
        field("name", 256, true)?;
        field("address", 1024, false)?;
        field("taxId", 64, false)?;
        field("email", 254, false)?;
        field("url", 512, false)?;
        field("paymentInstructions", 2048, false)?;
        let copy = issuer.cloned().unwrap_or_default();
        issuer_setting = Some(decode(copy)?);
    }
    let reminder_days = match &payment_reminder_days {
        Value::Array(items)
            if items.len() <= 10
                && items.iter().all(|item| {
                    core_js::as_number(item).is_some_and(|value| {
                        core_js::is_safe_integer(value) && (-60.0..=365.0).contains(&value)
                    })
                }) =>
        {
            items
                .iter()
                .filter_map(core_js::as_number)
                .collect::<Vec<f64>>()
        }
        _ => {
            return Err(settings_failure(
                "paymentReminderDays must list at most 10 whole days from -60 to 365",
            ));
        }
    };
    let mut payment_reminder_days: Vec<f64> = Vec::new();
    for day in reminder_days {
        if !payment_reminder_days.contains(&day) {
            payment_reminder_days.push(day);
        }
    }
    payment_reminder_days.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let currency = js_text(&currency);
    if !(currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase())) {
        return Err(settings_failure(
            "currency must be an ISO 4217 code such as USD",
        ));
    }
    let time_zone = js_text(&time_zone);
    if !crate::timezones::is_valid_time_zone(&time_zone) {
        return Err(settings_failure("timeZone must be an IANA time zone"));
    }
    let usage_retention_days = core_js::as_number(&usage_retention_days)
        .filter(|days| core_js::is_safe_integer(*days) && (1.0..=3650.0).contains(days))
        .ok_or_else(|| settings_failure("usageRetentionDays must be 1-3650"))?;
    let team_attribution = match team_attribution.as_str() {
        Some(value @ ("split" | "primary" | "full")) => value.to_owned(),
        _ => {
            return Err(settings_failure(
                "teamAttribution must be 'split', 'primary' or 'full'",
            ));
        }
    };
    let payment_terms_days = core_js::as_number(&payment_terms_days)
        .filter(|days| core_js::is_safe_integer(*days) && (0.0..=365.0).contains(days))
        .ok_or_else(|| settings_failure("paymentTermsDays must be 0-365"))?;
    let statement_prefix = js_text(&statement_prefix);
    let prefix_ok = {
        let bytes = statement_prefix.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 16
            && (bytes[0].is_ascii_uppercase() || bytes[0].is_ascii_digit())
            && bytes[1..]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'-')
    };
    if !prefix_ok {
        return Err(settings_failure(
            "statementPrefix must be 1-16 uppercase letters, digits or hyphens",
        ));
    }
    Ok(crate::billing::BillingSettings {
        currency,
        time_zone,
        usage_retention_days,
        team_attribution,
        payment_terms_days,
        statement_prefix,
        issuer: issuer_setting,
        payment_reminder_days,
        auto_finalize,
        extra: Map::new(),
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Money and periods

/// One unit of currency in micros.
pub const MICROS_PER_UNIT: f64 = 1_000_000.0;

/// `Math.round(value)`: halves round towards positive infinity, and `-0` stays `-0`.
pub(crate) fn js_round(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let floor = value.floor();
    let rounded = if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    };
    if rounded == 0.0 && value.is_sign_negative() {
        -0.0
    } else {
        rounded
    }
}

/// [`round_micros`] without the `Result`.
pub(crate) fn micros(value: f64) -> f64 {
    js_round(value * 1000.0) / 1000.0
}

/// [`round_cents`] without the `Result`.
pub(crate) fn cents(micros: f64) -> f64 {
    js_round(micros / 10_000.0) * 10_000.0
}

/// [`units_of`] without the `Result`.
pub(crate) fn units(micros: f64) -> f64 {
    js_round(micros / 10_000.0) / 100.0
}

/// Rounds micro amounts to a thousandth of a micro (prices per token are fractions of a micro).
pub fn round_micros(value: f64) -> IamResult<f64> {
    Ok(micros(value))
}

/// Micros rounded to a whole cent. Invoice amounts (lines, items, discounts, tax) are kept in cents so what an
/// invoice shows adds up; spend reports keep fractions of a cent.
pub fn round_cents(micros: f64) -> IamResult<f64> {
    Ok(cents(micros))
}

/// Micros as currency units, rounded to the cent.
pub fn units_of(micros: f64) -> IamResult<f64> {
    Ok(units(micros))
}

/// [`amount_micros`] for a JavaScript number.
pub(crate) fn amount_micros_of(value: Option<&Value>, name: &str) -> IamResult<f64> {
    match value.and_then(core_js::as_number) {
        Some(value) if value.is_finite() && (0.0..=1e9).contains(&value) => {
            Ok(micros(value * MICROS_PER_UNIT))
        }
        _ => Err(crate::js::invalid_input(format!(
            "{name} must be an amount from 0 to 1000000000"
        ))),
    }
}

/// An amount in currency units (a price or a budget) as micros: finite, 0 to one billion units.
pub fn amount_micros(value: Option<&Value>, name: &str) -> IamResult<f64> {
    amount_micros_of(value, name)
}

/// `/^(\d{4})-(0[1-9]|1[0-2])$/`.
fn is_period(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && matches!(
            (bytes[5], bytes[6]),
            (b'0', b'1'..=b'9') | (b'1', b'0'..=b'2')
        )
}

/// A billing period `YYYY-MM`.
pub fn billing_period(value: Option<&Value>, name: Option<&str>) -> IamResult<String> {
    match value {
        Some(Value::String(text)) if is_period(text) => Ok(text.clone()),
        _ => Err(crate::js::invalid_input(format!(
            "{} must be a month such as 2026-09",
            name.unwrap_or("period")
        ))),
    }
}

/// The wall-clock parts of an instant in a time zone (`formatToParts` with `hourCycle: 'h23'`).
struct ZoneParts {
    year: f64,
    month: f64,
    day: f64,
    hour: f64,
    minute: f64,
    second: f64,
}

fn zone_parts(at: f64, time_zone: &str) -> IamResult<ZoneParts> {
    let zone = crate::timezones::load_time_zone(time_zone)?;
    let invalid = || IamError::from(ThrownError::new("RangeError", "Invalid time value"));
    if !at.is_finite() || at.abs() > 8.64e15 {
        return Err(invalid());
    }
    let timestamp = Timestamp::from_millisecond(at.trunc() as i64).map_err(|_| invalid())?;
    let local = timestamp.to_zoned(zone);
    Ok(ZoneParts {
        year: f64::from(local.year()),
        month: f64::from(local.month()),
        day: f64::from(local.day()),
        hour: f64::from(local.hour() % 24),
        minute: f64::from(local.minute()),
        second: f64::from(local.second()),
    })
}

/// `Date.UTC(year, monthIndex, day, hour, minute, second)` (the month index may overflow, as JavaScript allows).
fn date_utc(year: f64, month_index: f64, day: f64, hour: f64, minute: f64, second: f64) -> f64 {
    let year = year + (month_index / 12.0).floor();
    let month = month_index.rem_euclid(12.0) + 1.0;
    let days = core_js::days_from_civil(year as i64, month as i64, 1) as f64 + (day - 1.0);
    days * 86_400_000.0 + hour * 3_600_000.0 + minute * 60_000.0 + second * 1000.0
}

/// Local wall-clock time minus UTC at an instant, in milliseconds.
fn zone_offset(at: f64, time_zone: &str) -> IamResult<f64> {
    let p = zone_parts(at, time_zone)?;
    Ok(
        date_utc(p.year, p.month - 1.0, p.day, p.hour, p.minute, p.second)
            - (at / 1000.0).floor() * 1000.0,
    )
}

/// The instant of local midnight on a date in a time zone.
fn local_midnight(year: f64, month: f64, day: f64, time_zone: &str) -> IamResult<f64> {
    let guess = date_utc(year, month - 1.0, day, 0.0, 0.0, 0.0);
    let first = guess - zone_offset(guess, time_zone)?;
    Ok(guess - zone_offset(first, time_zone)?)
}

/// `String(value).padStart(width, '0')`.
fn pad(value: f64, width: usize) -> String {
    let text = core_js::number_to_string(value);
    let length = text.chars().count();
    if length >= width {
        text
    } else {
        format!("{}{text}", "0".repeat(width - length))
    }
}

/// The billing period an instant falls in.
pub fn period_of(at: f64, time_zone: &str) -> IamResult<String> {
    let p = zone_parts(at, time_zone)?;
    Ok(format!("{}-{}", pad(p.year, 4), pad(p.month, 2)))
}

/// The local day `YYYY-MM-DD` an instant falls on.
pub fn day_of(at: f64, time_zone: &str) -> IamResult<String> {
    let p = zone_parts(at, time_zone)?;
    Ok(format!(
        "{}-{}-{}",
        pad(p.year, 4),
        pad(p.month, 2),
        pad(p.day, 2)
    ))
}

/// `period.split('-').map(Number)`: the year and month of a period.
fn period_numbers(period: &str) -> (f64, f64) {
    let mut parts = period.split('-').map(core_js::string_to_number);
    let year = parts.next().unwrap_or(f64::NAN);
    let month = parts.next().unwrap_or(f64::NAN);
    (year, month)
}

/// [`shift_period`] without the `Result`.
pub(crate) fn shift(period: &str, months: f64) -> String {
    let (year, month) = period_numbers(period);
    let index = year * 12.0 + (month - 1.0) + months;
    format!(
        "{}-{}",
        pad((index / 12.0).floor(), 4),
        pad((index % 12.0) + 1.0, 2)
    )
}

/// A period `months` after (or before, when negative) another.
pub fn shift_period(period: &str, months: f64) -> IamResult<String> {
    Ok(shift(period, months))
}

/// The first instant of a period and of the next one.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PeriodBounds {
    pub start: f64,
    pub end: f64,
}

/// [`period_bounds`] as a struct.
pub fn bounds_of(period: &str, time_zone: &str) -> IamResult<PeriodBounds> {
    let (year, month) = period_numbers(&billing_period(
        Some(&Value::String(period.to_owned())),
        None,
    )?);
    let (next_year, next_month) = period_numbers(&shift(period, 1.0));
    Ok(PeriodBounds {
        start: local_midnight(year, month, 1.0, time_zone)?,
        end: local_midnight(next_year, next_month, 1.0, time_zone)?,
    })
}

/// The first instant of a period and of the next one.
pub fn period_bounds(period: &str, time_zone: &str) -> IamResult<Value> {
    let bounds = bounds_of(period, time_zone)?;
    Ok(json!({ "start": number(bounds.start), "end": number(bounds.end) }))
}

/// The periods of the budget window containing `period`: the month, its calendar quarter, or its year.
pub fn window_periods(
    kind: &crate::billing::BudgetPeriodKind,
    period: &str,
) -> IamResult<Vec<String>> {
    let month = core_js::string_to_number(&period.chars().skip(5).take(2).collect::<String>());
    let kind = kind.as_str();
    let first = match kind {
        Some("month") => period.to_owned(),
        Some("quarter") => shift(period, -((month - 1.0) % 3.0)),
        _ => shift(period, -(month - 1.0)),
    };
    let length = match kind {
        Some("month") => 1,
        Some("quarter") => 3,
        _ => 12,
    };
    Ok((0..length)
        .map(|index| shift(&first, f64::from(index)))
        .collect())
}

// ---------------------------------------------------------------------------------------------------------------
// Meters and prices

/// `/^[a-z][a-z0-9_.-]{0,63}$/`.
pub(crate) fn is_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

/// A meter key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a letter.
pub fn meter_key(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(text)) if is_key(text) => Ok(text.clone()),
        _ => Err(crate::js::invalid_input(
            "meter must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter",
        )),
    }
}

/// `input.member ?? fallback`, with the fallback as a JSON value.
fn coalesce(input: &Map<String, Value>, key: &str, fallback: Value) -> Value {
    crate::js::defined(input.get(key))
        .cloned()
        .unwrap_or(fallback)
}

/// Validated meter settings; `current` supplies values an update leaves out.
pub fn meter_settings(
    input: &Map<String, Value>,
    current: Option<&crate::billing::BillingMeter>,
) -> IamResult<Value> {
    let name = match input.get("name") {
        None => current.map(|meter| meter.name.clone()),
        value => Some(core_js::trim(&text(value, "name", 128)?).to_owned()),
    };
    let name = match name {
        Some(name) if !name.is_empty() => name,
        _ => return Err(crate::js::invalid_input("name is required")),
    };
    let unit = match input.get("unit") {
        None => current
            .map(|meter| meter.unit.clone())
            .unwrap_or_else(|| "unit".to_owned()),
        value => core_js::trim(&text(value, "unit", 32)?).to_owned(),
    };
    let aggregation = coalesce(
        input,
        "aggregation",
        current
            .map(|meter| Value::String(meter.aggregation.clone()))
            .unwrap_or_else(|| json!("sum")),
    );
    let aggregation = match aggregation.as_str() {
        Some(value @ ("sum" | "unique")) => value.to_owned(),
        _ => {
            return Err(crate::js::invalid_input(
                "aggregation must be 'sum' or 'unique'",
            ));
        }
    };
    if let (Some(current), Some(value)) = (current, input.get("aggregation"))
        && value.as_str() != Some(current.aggregation.as_str())
    {
        return Err(crate::js::invalid_input(
            "A meter’s aggregation cannot change; create a new meter",
        ));
    }
    let pricing = coalesce(
        input,
        "pricing",
        current
            .map(|meter| Value::String(meter.pricing.clone()))
            .unwrap_or_else(|| json!("rate-card")),
    );
    let pricing = match pricing.as_str() {
        Some(value @ ("rate-card" | "reported")) => value.to_owned(),
        _ => {
            return Err(crate::js::invalid_input(
                "pricing must be 'rate-card' or 'reported'",
            ));
        }
    };
    if let (Some(current), Some(value)) = (current, input.get("pricing"))
        && value.as_str() != Some(current.pricing.as_str())
    {
        return Err(crate::js::invalid_input(
            "A meter’s pricing cannot change; create a new meter",
        ));
    }
    if pricing == "reported" && aggregation == "unique" {
        return Err(crate::js::invalid_input(
            "Reported meters add up their events (aggregation sum)",
        ));
    }
    let archived = coalesce(
        input,
        "archived",
        Value::Bool(current.is_some_and(|meter| meter.archived)),
    );
    let Value::Bool(archived) = archived else {
        return Err(crate::js::invalid_input("archived must be a boolean"));
    };
    let description = match input.get("description") {
        Some(Value::Null) => None,
        None => current.and_then(|meter| meter.description.clone()),
        value => Some(core_js::trim(&text(value, "description", 512)?).to_owned()),
    };
    let mut settings = Map::new();
    settings.insert("name".into(), Value::String(name));
    settings.insert("unit".into(), Value::String(unit));
    settings.insert("aggregation".into(), Value::String(aggregation));
    settings.insert("pricing".into(), Value::String(pricing));
    settings.insert("archived".into(), Value::Bool(archived));
    if let Some(description) = description {
        settings.insert("description".into(), Value::String(description));
    }
    Ok(Value::Object(settings))
}

fn quantity_limit(value: Option<&Value>, name: &str) -> IamResult<f64> {
    match value.and_then(core_js::as_number) {
        Some(value) if value.is_finite() && value > 0.0 && value <= 1e15 => Ok(value),
        _ => Err(crate::js::invalid_input(format!(
            "{name} must be a positive number"
        ))),
    }
}

/// `value !== undefined && value !== 0`.
fn set_and_nonzero(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(value) => core_js::as_number(value) != Some(0.0),
    }
}

/// Validates a price given in currency units (`unitAmount`, `tiers[].unitAmount` / `flatAmount`, `packageAmount`)
/// and returns it in micros. Tiers ascend by `upTo`, and the last one has `upTo: null`.
pub fn price_spec(value: Option<&Value>) -> IamResult<Value> {
    let input = object(value)?;
    let model = match input.get("model").and_then(Value::as_str) {
        Some(model @ ("per-unit" | "graduated" | "volume" | "package")) => model.to_owned(),
        _ => {
            return Err(crate::js::invalid_input(
                "model must be 'per-unit', 'graduated', 'volume' or 'package'",
            ));
        }
    };
    let mut spec = Map::new();
    spec.insert("model".into(), Value::String(model.clone()));
    if set_and_nonzero(input.get("includedQuantity")) {
        let included = quantity_limit(input.get("includedQuantity"), "includedQuantity")?;
        spec.insert("includedQuantity".into(), number(included));
    }
    if model == "per-unit" {
        let amount = amount_micros_of(input.get("unitAmount"), "unitAmount")?;
        spec.insert("unitAmountMicros".into(), number(amount));
    } else if model == "package" {
        let size = quantity_limit(input.get("packageSize"), "packageSize")?;
        spec.insert("packageSize".into(), number(size));
        let amount = amount_micros_of(input.get("packageAmount"), "packageAmount")?;
        spec.insert("packageAmountMicros".into(), number(amount));
    } else {
        let tiers = match input.get("tiers") {
            Some(Value::Array(tiers)) if !tiers.is_empty() && tiers.len() <= 20 => tiers,
            _ => return Err(crate::js::invalid_input("tiers must list 1-20 tiers")),
        };
        let mut previous = 0.0;
        let mut result_tiers = Vec::new();
        for (index, raw) in tiers.iter().enumerate() {
            let tier = object(Some(raw))?;
            let last = index == tiers.len() - 1;
            let up_to_null = matches!(tier.get("upTo"), Some(Value::Null));
            if if last { !up_to_null } else { up_to_null } {
                return Err(crate::js::invalid_input(
                    "Only the last tier has upTo: null",
                ));
            }
            let up_to = if up_to_null {
                None
            } else {
                Some(quantity_limit(tier.get("upTo"), "tiers.upTo")?)
            };
            if let Some(up_to) = up_to {
                if up_to <= previous {
                    return Err(crate::js::invalid_input("Tier upTo values must ascend"));
                }
                previous = up_to;
            }
            let unit_amount = coalesce(tier, "unitAmount", json!(0));
            let mut result = Map::new();
            result.insert("upTo".into(), up_to.map(number).unwrap_or(Value::Null));
            result.insert(
                "unitAmountMicros".into(),
                number(amount_micros_of(Some(&unit_amount), "tiers.unitAmount")?),
            );
            if set_and_nonzero(tier.get("flatAmount")) {
                result.insert(
                    "flatAmountMicros".into(),
                    number(amount_micros_of(
                        tier.get("flatAmount"),
                        "tiers.flatAmount",
                    )?),
                );
            }
            result_tiers.push(Value::Object(result));
        }
        spec.insert("tiers".into(), Value::Array(result_tiers));
    }
    let mut minimum = None;
    let mut maximum = None;
    if crate::js::defined(input.get("minimumAmount")).is_some() {
        let amount = amount_micros_of(input.get("minimumAmount"), "minimumAmount")?;
        spec.insert("minimumAmountMicros".into(), number(amount));
        minimum = Some(amount);
    }
    if crate::js::defined(input.get("maximumAmount")).is_some() {
        let amount = amount_micros_of(input.get("maximumAmount"), "maximumAmount")?;
        spec.insert("maximumAmountMicros".into(), number(amount));
        maximum = Some(amount);
    }
    if let (Some(minimum), Some(maximum)) = (minimum, maximum)
        && maximum < minimum
    {
        return Err(crate::js::invalid_input(
            "maximumAmount must not be below minimumAmount",
        ));
    }
    Ok(Value::Object(spec))
}

/// One tier of a stored price.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PriceTier {
    #[serde(default)]
    up_to: Option<f64>,
    #[serde(default)]
    unit_amount_micros: f64,
    #[serde(default)]
    flat_amount_micros: Option<f64>,
}

/// A stored price (`PriceSpec`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PriceSpec {
    #[serde(default)]
    model: String,
    #[serde(default)]
    unit_amount_micros: Option<f64>,
    #[serde(default)]
    tiers: Option<Vec<PriceTier>>,
    #[serde(default)]
    package_size: Option<f64>,
    #[serde(default)]
    package_amount_micros: Option<f64>,
    #[serde(default)]
    included_quantity: Option<f64>,
    #[serde(default)]
    minimum_amount_micros: Option<f64>,
    #[serde(default)]
    maximum_amount_micros: Option<f64>,
}

fn read_spec(spec: &Value) -> IamResult<PriceSpec> {
    serde_json::from_value(spec.clone()).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

/// A quantity's amount under a price's tiers and free units, before its minimum and maximum.
fn tiered_amount(spec: &PriceSpec, quantity: f64) -> f64 {
    let units = (quantity - spec.included_quantity.unwrap_or(0.0)).max(0.0);
    if units == 0.0 {
        return 0.0;
    }
    let tiers = spec.tiers.as_deref().unwrap_or(&[]);
    match spec.model.as_str() {
        "per-unit" => micros(units * spec.unit_amount_micros.unwrap_or(0.0)),
        "package" => micros(
            (units / spec.package_size.unwrap_or(1.0)).ceil()
                * spec.package_amount_micros.unwrap_or(0.0),
        ),
        "volume" => {
            let Some(tier) = tiers
                .iter()
                .find(|candidate| candidate.up_to.is_none_or(|up_to| units <= up_to))
                .or(tiers.last())
            else {
                return f64::NAN;
            };
            micros(units * tier.unit_amount_micros + tier.flat_amount_micros.unwrap_or(0.0))
        }
        "graduated" => {
            let mut total = 0.0;
            let mut lower = 0.0;
            for tier in tiers {
                let upper = tier.up_to.unwrap_or(f64::INFINITY);
                let in_tier = units.min(upper) - lower;
                if in_tier <= 0.0 {
                    break;
                }
                total += in_tier * tier.unit_amount_micros + tier.flat_amount_micros.unwrap_or(0.0);
                lower = upper;
            }
            micros(total)
        }
        _ => f64::NAN,
    }
}

/// [`price_quantity`] for a decoded price.
fn price_amount(spec: &PriceSpec, quantity: f64) -> f64 {
    let raw = tiered_amount(spec, quantity);
    if quantity <= 0.0 {
        return raw;
    }
    let mut amount = raw;
    if let Some(minimum) = spec.minimum_amount_micros {
        amount = js_max(amount, minimum);
    }
    if let Some(maximum) = spec.maximum_amount_micros {
        amount = js_min(amount, maximum);
    }
    micros(amount)
}

/// `Math.max(a, b)` (NaN wins).
pub(crate) fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.min(a, b)` (NaN wins).
pub(crate) fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// The amount, in micros, a period's quantity costs under a price: its tiers, then its minimum and maximum.
pub fn price_quantity(spec: &Value, quantity: f64) -> IamResult<f64> {
    Ok(price_amount(&read_spec(spec)?, quantity))
}

/// How a quantity is priced, tier by tier, for invoice sub-lines: the tiers used, the free units, and what the
/// tiers came to before the price's minimum or maximum.
pub fn price_breakdown(spec: &Value, quantity: f64) -> IamResult<Value> {
    let spec = read_spec(spec)?;
    let included = js_min(quantity, spec.included_quantity.unwrap_or(0.0));
    let units = js_max(0.0, quantity - included);
    let mut tiers: Vec<Value> = Vec::new();
    let tier_line =
        |from: f64, to: Option<f64>, quantity: f64, tier: &PriceTier, amount: f64| -> Value {
            let mut line = Map::new();
            line.insert("from".into(), number(from));
            line.insert("to".into(), to.map(number).unwrap_or(Value::Null));
            line.insert("quantity".into(), number(quantity));
            line.insert("unitAmountMicros".into(), number(tier.unit_amount_micros));
            if let Some(flat) = tier.flat_amount_micros {
                line.insert("flatAmountMicros".into(), number(flat));
            }
            line.insert("amountMicros".into(), number(amount));
            Value::Object(line)
        };
    if units > 0.0 && (spec.model == "graduated" || spec.model == "volume") {
        let mut lower = 0.0;
        for tier in spec.tiers.as_deref().unwrap_or(&[]) {
            let upper = tier.up_to.unwrap_or(f64::INFINITY);
            if spec.model == "volume" {
                if let Some(up_to) = tier.up_to
                    && units > up_to
                {
                    lower = upper;
                    continue;
                }
                tiers.push(tier_line(
                    lower + 1.0,
                    tier.up_to,
                    units,
                    tier,
                    micros(
                        units * tier.unit_amount_micros + tier.flat_amount_micros.unwrap_or(0.0),
                    ),
                ));
                break;
            }
            let in_tier = units.min(upper) - lower;
            if in_tier <= 0.0 {
                break;
            }
            tiers.push(tier_line(
                lower + 1.0,
                tier.up_to,
                js_round(in_tier * 1e6) / 1e6,
                tier,
                micros(in_tier * tier.unit_amount_micros + tier.flat_amount_micros.unwrap_or(0.0)),
            ));
            lower = upper;
        }
    }
    let mut result = Map::new();
    result.insert("tiers".into(), Value::Array(tiers));
    if included > 0.0 {
        result.insert("includedQuantity".into(), number(included));
    }
    result.insert("rawMicros".into(), number(tiered_amount(&spec, quantity)));
    Ok(Value::Object(result))
}

/// A price in currency units, as the API shows it.
pub fn public_price_spec(spec: &Value) -> IamResult<Value> {
    let units = |value: &Value| number(core_js::to_number(value) / MICROS_PER_UNIT);
    let mut result = Map::new();
    if let Some(model) = spec.get("model") {
        result.insert("model".into(), model.clone());
    }
    if let Some(amount) = spec.get("unitAmountMicros") {
        result.insert("unitAmount".into(), units(amount));
    }
    if let Some(tiers) = spec
        .get("tiers")
        .filter(|tiers| crate::js::truthy(Some(tiers)))
    {
        let list: Vec<Value> = tiers
            .as_array()
            .map(|tiers| {
                tiers
                    .iter()
                    .map(|tier| {
                        let mut entry = Map::new();
                        if let Some(up_to) = tier.get("upTo") {
                            entry.insert("upTo".into(), up_to.clone());
                        }
                        entry.insert(
                            "unitAmount".into(),
                            tier.get("unitAmountMicros")
                                .map(units)
                                .unwrap_or(Value::Null),
                        );
                        if let Some(flat) = tier.get("flatAmountMicros") {
                            entry.insert("flatAmount".into(), units(flat));
                        }
                        Value::Object(entry)
                    })
                    .collect()
            })
            .unwrap_or_default();
        result.insert("tiers".into(), Value::Array(list));
    }
    if let Some(size) = spec.get("packageSize") {
        result.insert("packageSize".into(), size.clone());
    }
    if let Some(amount) = spec.get("packageAmountMicros") {
        result.insert("packageAmount".into(), units(amount));
    }
    if let Some(included) = spec.get("includedQuantity") {
        result.insert("includedQuantity".into(), included.clone());
    }
    if let Some(amount) = spec.get("minimumAmountMicros") {
        result.insert("minimumAmount".into(), units(amount));
    }
    if let Some(amount) = spec.get("maximumAmountMicros") {
        result.insert("maximumAmount".into(), units(amount));
    }
    Ok(Value::Object(result))
}

/// The meter a key names for a tenant: the one its ancestor nearest the root defines.
pub async fn resolve_meter(
    tx: &Store,
    chain: &[better_iam_core::Tenant],
    key: &str,
) -> IamResult<Option<crate::billing::BillingMeter>> {
    for realm in chain.iter().rev() {
        let found = find_typed::<BillingMeter>(
            tx,
            METERS,
            Filter::new()
                .eq("tenantId", realm.id.as_str())
                .eq("uniqueKey", key),
        )
        .await?
        .into_iter()
        .next();
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// Every meter that reaches a tenant, keyed by key (ancestors nearest the root win a shared key).
pub async fn meters_for(
    tx: &Store,
    chain: &[better_iam_core::Tenant],
) -> IamResult<IndexMap<String, crate::billing::BillingMeter>> {
    let mut meters: IndexMap<String, BillingMeter> = IndexMap::new();
    for realm in chain.iter().rev() {
        for meter in
            find_typed::<BillingMeter>(tx, METERS, Filter::new().eq("tenantId", realm.id.as_str()))
                .await?
        {
            if !meters.contains_key(&meter.key) {
                meters.insert(meter.key.clone(), meter);
            }
        }
    }
    Ok(meters)
}

/// The price of a meter for a tenant in a period: walking from `chain[0]` up to the meter's defining tenant, the
/// first tenant with an entry effective by then (the latest such entry).
pub async fn price_for(
    tx: &Store,
    meter: &crate::billing::BillingMeter,
    chain: &[better_iam_core::Tenant],
    period: &str,
) -> IamResult<Option<crate::billing::BillingPrice>> {
    for realm in chain {
        let mut entries: Vec<BillingPrice> = find_typed::<BillingPrice>(
            tx,
            PRICES,
            Filter::new()
                .eq("tenantId", realm.id.as_str())
                .eq("meterId", meter.id.as_str()),
        )
        .await?
        .into_iter()
        .filter(|entry| core_js::cmp_utf16(&entry.effective_from, period).is_le())
        .collect();
        entries.sort_by(|a, b| core_js::cmp_utf16(&b.effective_from, &a.effective_from));
        if let Some(entry) = entries.into_iter().next() {
            return Ok(Some(entry));
        }
        if realm.id == meter.tenant_id {
            break;
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------------------------------------------
// Usage

/// `/^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/`.
fn is_tag_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Validated tags: at most 10, keys like `project` or `env.name`, values up to 128 characters.
pub fn usage_tags(value: Option<&Value>) -> IamResult<Option<IndexMap<String, String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let input = object(Some(value))?;
    let mut entries = core_js::entries(input);
    if entries.len() > 10 {
        return Err(crate::js::invalid_input("tags may hold at most 10 entries"));
    }
    if entries.is_empty() {
        return Ok(None);
    }
    entries.sort_by(|(a, _), (b, _)| core_js::cmp_utf16(a, b));
    let mut tags = IndexMap::new();
    for (key, raw) in entries {
        if !is_tag_key(key) {
            return Err(crate::js::invalid_input(format!("Invalid tag name {key}")));
        }
        tags.insert(key.clone(), text(Some(raw), &format!("tags.{key}"), 128)?);
    }
    Ok(Some(tags))
}

/// `createHash('sha256').update(value).digest('base64url')`.
fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// Deterministic id of the daily bucket for a usage attribution.
pub fn rollup_id(
    tenant_id: &str,
    day: &str,
    meter_id: &str,
    attribution: &Value,
) -> IamResult<String> {
    let member = |key: &str| {
        crate::js::defined(attribution.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let list = Value::Array(vec![
        json!(tenant_id),
        json!(day),
        json!(meter_id),
        member("identityId"),
        member("agentId"),
        attribution.get("teamIds").cloned().unwrap_or(Value::Null),
        member("departmentId"),
        member("tags"),
    ]);
    let hashed = digest(&core_js::stringify(&list));
    Ok(format!("r_{}", &hashed[..32]))
}

/// Resolves attribution for an identity recording or causing usage in `tenant`. The identity must belong to the
/// tenant or one of its ancestors and not be deleted. An agent's usage is attributed to the agent and to its
/// sponsor's teams and department; `teamId` (a team of the identity's tenant) replaces the person's own teams.
pub async fn attribution_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    chain: &[better_iam_core::Tenant],
    input: &Value,
    settings: &crate::billing::BillingSettings,
) -> IamResult<Value> {
    let mut result = Map::new();
    result.insert("teamIds".into(), json!([]));
    let Some(identity_id) = input.get("identityId") else {
        if let Some(team_id) = input.get("teamId") {
            result.insert(
                "teamIds".into(),
                json!([team_in(tx, chain, Some(team_id)).await?]),
            );
        }
        return Ok(Value::Object(result));
    };
    let identity_id = text(Some(identity_id), "identityId", 256)?;
    let identity: Option<Identity> = get_typed(tx, "identities", &identity_id).await?;
    let identity = match identity {
        Some(identity)
            if identity.status != IdentityStatus::Deleted
                && chain.iter().any(|realm| realm.id == identity.tenant_id) =>
        {
            identity
        }
        _ => {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Identity not found",
                404,
            ));
        }
    };
    result.insert("identityId".into(), json!(identity.id));
    if let Some(agent_id) = input.get("agentId") {
        result.insert(
            "agentId".into(),
            json!(text(Some(agent_id), "agentId", 256)?),
        );
    } else if identity.kind == IdentityKind::Agent {
        result.insert("agentId".into(), json!(identity.id));
    }
    // Agents count toward the person answerable for them.
    let person = match (&identity.kind, &identity.agent) {
        (IdentityKind::Agent, Some(agent)) if !agent.sponsor_id.is_empty() => {
            agent.sponsor_id.clone()
        }
        _ => identity.id.clone(),
    };
    let at = ctx.now();
    let team_ids: Vec<String> = if let Some(team_id) = input.get("teamId") {
        vec![team_in(tx, chain, Some(team_id)).await?]
    } else {
        let teams =
            crate::teams::teams_of_at(tx, &identity.tenant_id, &person, Some(at), false).await?;
        if settings.team_attribution == "primary" {
            teams.into_iter().take(1).collect()
        } else {
            teams
        }
    };
    result.insert("teamIds".into(), json!(team_ids));
    let mut department_id =
        crate::departments::department_of(tx, &identity.tenant_id, &person).await?;
    if department_id.as_deref().is_none_or(str::is_empty)
        && let Some(first) = team_ids.first().filter(|first| !first.is_empty())
    {
        let team: Option<crate::teams::Team> = get_typed(tx, TEAMS, first).await?;
        department_id = team.and_then(|team| team.department_id);
    }
    if let Some(department_id) = department_id.filter(|id| !id.is_empty()) {
        result.insert("departmentId".into(), json!(department_id));
    }
    Ok(Value::Object(result))
}

/// The `teams` collection (`teamCollections.teams`).
const TEAMS: &str = "teams";

async fn team_in(
    tx: &Store,
    chain: &[better_iam_core::Tenant],
    team_id: Option<&Value>,
) -> IamResult<String> {
    let team_id = text(team_id, "teamId", 256)?;
    let team: Option<crate::teams::Team> = get_typed(tx, TEAMS, &team_id).await?;
    match team {
        Some(team) if chain.iter().any(|realm| realm.id == team.tenant_id) => Ok(team.id),
        _ => Err(IamError::with_status("NOT_FOUND", "Team not found", 404)),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Billing accounts and profiles

pub async fn profile_of(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<crate::billing::BillingProfile>> {
    Ok(find_typed(
        tx,
        PROFILES,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("uniqueKey", "profile"),
    )
    .await?
    .into_iter()
    .next())
}

/// The billing account of a tenant: the nearest tenant (itself or above) with a profile, else its organization.
pub async fn account_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
) -> IamResult<better_iam_core::Tenant> {
    let chain = ctx.ancestry(tx, tenant).await?;
    for realm in &chain[..chain.len().saturating_sub(1)] {
        if profile_of(tx, &realm.id).await?.is_some() {
            return Ok(realm.clone());
        }
    }
    // The organization directly below the root (the root pays for itself).
    Ok(if chain.len() > 1 {
        chain[chain.len() - 2].clone()
    } else {
        chain[0].clone()
    })
}

async fn children(tx: &Store, parent_id: &str) -> IamResult<Vec<Tenant>> {
    let mut list: Vec<Tenant> =
        find_typed(tx, "tenants", Filter::new().eq("parentId", parent_id)).await?;
    list.sort_by(|a, b| core_js::cmp_utf16(&a.id, &b.id));
    Ok(list)
}

/// A tenant and every tenant below it.
pub async fn subtree(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
) -> IamResult<Vec<better_iam_core::Tenant>> {
    let _ = ctx;
    let mut result: Vec<Tenant> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut queue: std::collections::VecDeque<Tenant> = std::collections::VecDeque::new();
    queue.push_back(tenant.clone());
    while result.len() < 100_000 {
        let Some(next) = queue.pop_front() else { break };
        if seen.contains(&next.id) {
            continue;
        }
        seen.insert(next.id.clone());
        let id = next.id.clone();
        result.push(next);
        queue.extend(children(tx, &id).await?);
    }
    Ok(result)
}

/// The tenants an account pays for: its subtree, minus subtrees of tenants that have a profile of their own.
pub async fn account_tenants(
    tx: &Store,
    account: &better_iam_core::Tenant,
    is_root: bool,
) -> IamResult<Vec<better_iam_core::Tenant>> {
    let mut result: Vec<Tenant> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut queue: std::collections::VecDeque<Tenant> = std::collections::VecDeque::new();
    queue.push_back(account.clone());
    while result.len() < 100_000 {
        let Some(next) = queue.pop_front() else { break };
        if seen.contains(&next.id) {
            continue;
        }
        seen.insert(next.id.clone());
        let id = next.id.clone();
        result.push(next);
        for child in children(tx, &id).await? {
            // Below the root every organization is an account of its own.
            if is_root && id == account.id {
                continue;
            }
            if profile_of(tx, &child.id).await?.is_some() {
                continue;
            }
            queue.push_back(child);
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------------------------------------------
// Spend

/// A plan's price for a meter over the local days (`YYYY-MM-DD`, inclusive) a subscription to it was live on.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanPriceWindow {
    pub spec: Value,
    pub plan_key: String,
    pub from: String,
    pub to: String,
}

/// The prices an account's subscriptions give a meter in a period, oldest subscription first: for each subscription
/// whose plan has a usage item for the meter, the days of the period it was live on. A day's usage takes the first
/// window that covers it; usage on days no subscription covers (before it started, after it ended) keeps rate-card
/// prices.
pub async fn plan_prices_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account_id: &str,
    meter: &str,
    period: &str,
) -> IamResult<Vec<PlanPriceWindow>> {
    let mut subscriptions: Vec<BillingSubscription> =
        find_typed(tx, SUBSCRIPTIONS, Filter::new().eq("tenantId", account_id)).await?;
    if subscriptions.is_empty() {
        return Ok(Vec::new());
    }
    let time_zone = ctx
        .options
        .billing
        .as_ref()
        .and_then(|billing| billing.time_zone.clone())
        .unwrap_or_else(|| "UTC".to_owned());
    let bounds = bounds_of(period, &time_zone)?;
    let mut windows = Vec::new();
    subscriptions.sort_by(by_start);
    for subscription in &subscriptions {
        let from = bounds.start.max(subscription.started_at);
        let to = bounds
            .end
            .min(subscription.ends_at.unwrap_or(f64::INFINITY));
        if to <= from {
            continue;
        }
        let plan: Option<BillingPlan> = get_typed(tx, PLANS, &subscription.plan_id).await?;
        let Some(plan) = plan else { continue };
        let item = plan.items.iter().find(|candidate| {
            candidate.kind == "usage" && candidate.meter.as_deref() == Some(meter)
        });
        if let Some(price) = item
            .and_then(|item| item.price.as_ref())
            .filter(|price| crate::js::truthy(Some(price)))
        {
            windows.push(PlanPriceWindow {
                spec: price.clone(),
                plan_key: plan.key.clone(),
                from: day_of(from, &time_zone)?,
                to: day_of(to - 1.0, &time_zone)?,
            });
        }
    }
    Ok(windows)
}

/// `a.startedAt - b.startedAt || (a.id < b.id ? -1 : 1)`.
pub(crate) fn by_start(a: &BillingSubscription, b: &BillingSubscription) -> std::cmp::Ordering {
    a.started_at
        .partial_cmp(&b.started_at)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| core_js::cmp_utf16(&a.id, &b.id))
}

/// What `accountSpend` computes for an account and period.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSpend {
    pub account_id: String,
    pub period: String,
    pub charges: Vec<MeterCharge>,
    pub rows: Vec<ChargedRow>,
    /// Everything, chargeback meters included.
    pub total_micros: f64,
    /// What a statement would bill: meters defined above the account.
    pub billable_micros: f64,
}

/// What `scopeSpend` computes for a subtree and period.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeSpend {
    pub rows: Vec<ChargedRow>,
    pub accounts: Vec<AccountSpend>,
}

impl SpendCache {
    /// An empty cache (`new Map()`).
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &str) -> Option<IamResult<AccountSpend>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned()
    }

    fn set(&self, key: String, value: IamResult<AccountSpend>) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, value);
    }
}

/// Prices every meter used in an account's tenants during a period and allocates the cost to the usage.
pub async fn account_spend(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &better_iam_core::Tenant,
    period: &str,
    cache: Option<&crate::billing::SpendCache>,
) -> IamResult<Value> {
    let spend = account_spend_of(ctx, tx, account, period, cache).await?;
    Ok(Value::Object(encode(&spend)))
}

/// [`account_spend`] as a struct.
pub async fn account_spend_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &Tenant,
    period: &str,
    cache: Option<&SpendCache>,
) -> IamResult<AccountSpend> {
    let key = format!("{}:{period}", account.id);
    if let Some(cached) = cache.and_then(|cache| cache.get(&key)) {
        return cached;
    }
    let computed = compute_account_spend(ctx, tx, account, period).await;
    if let Some(cache) = cache {
        cache.set(key, computed.clone());
    }
    computed
}

/// `row.agentId ?? row.identityId`.
fn principal_of(row: &ChargedRow) -> Option<&String> {
    row.agent_id.as_ref().or(row.identity_id.as_ref())
}

async fn compute_account_spend(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    account: &Tenant,
    period: &str,
) -> IamResult<AccountSpend> {
    let account_chain = ctx.ancestry(tx, account).await?;
    let tenants = account_tenants(tx, account, account.parent_id.is_none()).await?;
    let mut by_meter: IndexMap<String, Vec<BillingRollup>> = IndexMap::new();
    for realm in &tenants {
        for rollup in find_typed::<BillingRollup>(
            tx,
            ROLLUPS,
            Filter::new()
                .eq("tenantId", realm.id.as_str())
                .eq("period", period),
        )
        .await?
        {
            by_meter
                .entry(rollup.meter_id.clone())
                .or_default()
                .push(rollup);
        }
    }
    let mut groups: Vec<(String, Vec<BillingRollup>)> = by_meter.into_iter().collect();
    groups.sort_by(|(a, _), (b, _)| core_js::cmp_utf16(a, b));
    let mut charges: Vec<MeterCharge> = Vec::new();
    let mut rows: Vec<ChargedRow> = Vec::new();
    for (meter_id, rollups) in groups {
        let meter: Option<BillingMeter> = get_typed(tx, METERS, &meter_id).await?;
        let first = &rollups[0];
        let defined_above = account_chain[1..]
            .iter()
            .any(|realm| Some(&realm.id) == meter.as_ref().map(|meter| &meter.tenant_id));
        let internal = !defined_above && account.parent_id.is_some();
        let charge = MeterCharge {
            meter_id: meter_id.clone(),
            meter: meter
                .as_ref()
                .map(|meter| meter.key.clone())
                .unwrap_or_else(|| first.meter.clone()),
            name: meter
                .as_ref()
                .map(|meter| meter.name.clone())
                .unwrap_or_else(|| first.meter.clone()),
            unit: meter
                .as_ref()
                .map(|meter| meter.unit.clone())
                .unwrap_or_else(|| "unit".to_owned()),
            defined_by: meter
                .as_ref()
                .map(|meter| meter.tenant_id.clone())
                .unwrap_or_default(),
            internal,
            aggregation: meter
                .as_ref()
                .map(|meter| meter.aggregation.clone())
                .unwrap_or_else(|| "sum".to_owned()),
            pricing: meter
                .as_ref()
                .map(|meter| meter.pricing.clone())
                .unwrap_or_else(|| "reported".to_owned()),
            quantity: 0.0,
            amount_micros: 0.0,
            price: None,
            unpriced: None,
            extra: Map::new(),
        };
        let mut charged: Vec<ChargedRow> = rollups
            .iter()
            .map(|rollup| ChargedRow {
                tenant_id: rollup.tenant_id.clone(),
                period: period.to_owned(),
                day: rollup.day.clone(),
                meter_id: meter_id.clone(),
                meter: charge.meter.clone(),
                identity_id: rollup.identity_id.clone(),
                agent_id: rollup.agent_id.clone(),
                team_ids: rollup.team_ids.clone(),
                department_id: rollup.department_id.clone(),
                tags: rollup.tags.clone(),
                quantity: rollup.quantity,
                cost_micros: 0.0,
                events: rollup.events,
                internal,
                extra: Map::new(),
            })
            .collect();
        let unique = charge.aggregation == "unique";
        let quantity_of = |list: &[&ChargedRow]| -> f64 {
            if unique {
                let principals: IndexSet<&String> = list
                    .iter()
                    .filter_map(|row| principal_of(row))
                    .filter(|principal| !principal.is_empty())
                    .collect();
                principals.len() as f64
            } else {
                list.iter().fold(0.0, |sum, row| sum + row.quantity)
            }
        };
        match meter.as_ref().filter(|_| charge.pricing != "reported") {
            None => {
                let mut charge = charge;
                charge.quantity = quantity_of(&charged.iter().collect::<Vec<_>>());
                for (row, rollup) in charged.iter_mut().zip(&rollups) {
                    row.cost_micros = micros(rollup.cost_micros);
                }
                charge.amount_micros =
                    micros(charged.iter().fold(0.0, |sum, row| sum + row.cost_micros));
                charges.push(charge);
            }
            Some(meter) => {
                // Tiers apply to the account's period total; the meter's own tenant prices meters defined inside
                // the account.
                let price_chain = if defined_above {
                    account_chain.clone()
                } else {
                    let owner: Option<Tenant> = get_typed(tx, "tenants", &meter.tenant_id).await?;
                    ctx.ancestry(tx, owner.as_ref().unwrap_or(account)).await?
                };
                // A subscription's plan price replaces the rate card for platform meters, for the days it was live
                // only.
                let windows = if defined_above {
                    plan_prices_for(ctx, tx, &account.id, &meter.key, period).await?
                } else {
                    Vec::new()
                };
                // Each row's price: the first plan window covering its day, or the rate card (-1). A `unique` meter
                // counts a person once, at the price of the first window they have usage in.
                let mut group_of: Vec<i64> = charged
                    .iter()
                    .map(|row| {
                        windows
                            .iter()
                            .position(|window| {
                                core_js::cmp_utf16(&row.day, &window.from).is_ge()
                                    && core_js::cmp_utf16(&row.day, &window.to).is_le()
                            })
                            .map_or(-1, |index| index as i64)
                    })
                    .collect();
                if unique {
                    let mut earliest: IndexMap<String, i64> = IndexMap::new();
                    for (index, row) in charged.iter().enumerate() {
                        let group = group_of[index];
                        if let Some(principal) = principal_of(row).filter(|p| !p.is_empty()) {
                            let known = earliest.get(principal).copied();
                            if group >= 0 && known.is_none_or(|known| group < known) {
                                earliest.insert(principal.clone(), group);
                            }
                        }
                    }
                    for (index, row) in charged.iter().enumerate() {
                        if let Some(principal) = principal_of(row).filter(|p| !p.is_empty()) {
                            group_of[index] = earliest.get(principal).copied().unwrap_or(-1);
                        }
                    }
                }
                let mut distinct: Vec<i64> = Vec::new();
                for group in &group_of {
                    if !distinct.contains(group) {
                        distinct.push(*group);
                    }
                }
                distinct.sort();
                for group in distinct {
                    let members: Vec<usize> = (0..charged.len())
                        .filter(|index| group_of[*index] == group)
                        .collect();
                    let mut part = charge.clone();
                    part.quantity = quantity_of(
                        &members
                            .iter()
                            .map(|index| &charged[*index])
                            .collect::<Vec<_>>(),
                    );
                    let planned = usize::try_from(group)
                        .ok()
                        .and_then(|group| windows.get(group));
                    let price = if planned.is_some() {
                        None
                    } else {
                        price_for(tx, meter, &price_chain, period).await?
                    };
                    if let Some(planned) = planned {
                        let mut price = Map::new();
                        price.insert("effectiveFrom".into(), json!(period));
                        price.insert("setOn".into(), json!(account.id));
                        price.insert("spec".into(), planned.spec.clone());
                        price.insert("source".into(), json!("plan"));
                        price.insert("planKey".into(), json!(planned.plan_key));
                        part.price = Some(Value::Object(price));
                        part.amount_micros =
                            price_amount(&read_spec(&planned.spec)?, part.quantity);
                    } else if let Some(price) = price {
                        let mut entry = Map::new();
                        entry.insert("effectiveFrom".into(), json!(price.effective_from));
                        entry.insert("setOn".into(), json!(price.tenant_id));
                        entry.insert("spec".into(), price.spec.clone());
                        entry.insert("source".into(), json!("rate-card"));
                        part.price = Some(Value::Object(entry));
                        part.amount_micros = price_amount(&read_spec(&price.spec)?, part.quantity);
                    } else {
                        part.unpriced = Some(true);
                    }
                    if part.amount_micros > 0.0 && part.quantity > 0.0 {
                        if part.aggregation == "unique" {
                            // Each person or agent costs the same; their share is spread over their rows by quantity.
                            let each = part.amount_micros / part.quantity;
                            let mut per_principal: IndexMap<String, Vec<usize>> = IndexMap::new();
                            for index in &members {
                                if let Some(principal) =
                                    principal_of(&charged[*index]).filter(|p| !p.is_empty())
                                {
                                    per_principal
                                        .entry(principal.clone())
                                        .or_default()
                                        .push(*index);
                                }
                            }
                            for rows_of in per_principal.values() {
                                let total = rows_of
                                    .iter()
                                    .fold(0.0, |sum, index| sum + charged[*index].quantity);
                                for index in rows_of {
                                    let row = &mut charged[*index];
                                    row.cost_micros = micros(if total > 0.0 {
                                        (each * row.quantity) / total
                                    } else {
                                        each / rows_of.len() as f64
                                    });
                                }
                            }
                        } else {
                            for index in &members {
                                let row = &mut charged[*index];
                                row.cost_micros =
                                    micros((part.amount_micros * row.quantity) / part.quantity);
                            }
                        }
                    }
                    charges.push(part);
                }
            }
        }
        rows.extend(charged);
    }
    charges.sort_by(|a, b| {
        let difference = b.amount_micros - a.amount_micros;
        if difference > 0.0 {
            std::cmp::Ordering::Greater
        } else if difference < 0.0 {
            std::cmp::Ordering::Less
        } else {
            core_js::cmp_utf16(&a.meter, &b.meter)
        }
    });
    let total_micros = micros(
        charges
            .iter()
            .fold(0.0, |sum, charge| sum + charge.amount_micros),
    );
    let billable_micros = micros(
        charges
            .iter()
            .filter(|charge| !charge.internal)
            .fold(0.0, |sum, charge| sum + charge.amount_micros),
    );
    Ok(AccountSpend {
        account_id: account.id.clone(),
        period: period.to_owned(),
        charges,
        rows,
        total_micros,
        billable_micros,
    })
}

/// Spend of a tenant's subtree in a period: the charged usage of every tenant below (and including) it, priced
/// within the billing account each tenant belongs to. For the root this is the whole platform.
pub async fn scope_spend(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    scope: &better_iam_core::Tenant,
    period: &str,
    cache: Option<&crate::billing::SpendCache>,
) -> IamResult<Value> {
    let spend = scope_spend_of(ctx, tx, scope, period, cache).await?;
    Ok(Value::Object(encode(&spend)))
}

/// [`scope_spend`] as a struct.
pub async fn scope_spend_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    scope: &Tenant,
    period: &str,
    cache: Option<&SpendCache>,
) -> IamResult<ScopeSpend> {
    let tenants = subtree(ctx, tx, scope).await?;
    let in_scope: IndexSet<&str> = tenants.iter().map(|realm| realm.id.as_str()).collect();
    let root_id = ctx
        .ancestry(tx, scope)
        .await?
        .last()
        .map(|realm| realm.id.clone())
        .unwrap_or_default();
    let mut account_ids: IndexMap<String, Tenant> = IndexMap::new();
    let top = account_of(ctx, tx, scope).await?;
    account_ids.insert(top.id.clone(), top);
    // Organizations directly below the root, and tenants with a profile, are accounts of their own.
    for realm in tenants.iter().skip(1) {
        if realm.parent_id.as_deref() == Some(root_id.as_str())
            || profile_of(tx, &realm.id).await?.is_some()
        {
            account_ids.insert(realm.id.clone(), realm.clone());
        }
    }
    let mut accounts = Vec::new();
    let mut rows = Vec::new();
    for account in account_ids.values() {
        let spend = account_spend_of(ctx, tx, account, period, cache).await?;
        for row in &spend.rows {
            if in_scope.contains(row.tenant_id.as_str()) {
                rows.push(row.clone());
            }
        }
        accounts.push(spend);
    }
    Ok(ScopeSpend { rows, accounts })
}

/// Totals of charged rows (cost and events).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RowTotals {
    pub cost_micros: f64,
    pub events: f64,
}

/// Totals of charged rows (cost and per-meter quantity).
pub fn sum_rows(rows: &[ChargedRow]) -> RowTotals {
    RowTotals {
        cost_micros: micros(rows.iter().fold(0.0, |sum, row| sum + row.cost_micros)),
        events: rows.iter().fold(0.0, |sum, row| sum + row.events),
    }
}

pub async fn directory_for(tx: &Store, tenant_ids: &Value) -> IamResult<crate::billing::Directory> {
    let mut teams: IndexMap<String, crate::teams::Team> = IndexMap::new();
    let mut departments: IndexMap<String, crate::departments::Department> = IndexMap::new();
    let mut unique: IndexSet<String> = IndexSet::new();
    for tenant_id in tenant_ids.as_array().into_iter().flatten() {
        unique.insert(crate::js::js_string(Some(tenant_id)));
    }
    for tenant_id in &unique {
        for team in find_typed::<crate::teams::Team>(
            tx,
            TEAMS,
            Filter::new().eq("tenantId", tenant_id.as_str()),
        )
        .await?
        {
            teams.insert(team.id.clone(), team);
        }
        for (id, department) in crate::departments::tenant_departments(tx, tenant_id).await? {
            departments.insert(id, department);
        }
    }
    Ok(Directory {
        teams,
        departments,
        extra: Map::new(),
    })
}

/// The share of a row's cost that counts toward `teamId` (and the teams above it when `rollUp`).
pub fn team_share(
    row: &crate::billing::ChargedRow,
    team_id: &str,
    directory: &crate::billing::Directory,
    settings: &crate::billing::BillingSettings,
    roll_up: bool,
) -> IamResult<f64> {
    if row.team_ids.is_empty() {
        return Ok(0.0);
    }
    let matching = row
        .team_ids
        .iter()
        .filter(|id| {
            if roll_up {
                crate::teams::team_chain_of(&directory.teams, id)
                    .iter()
                    .any(|team| team.id == team_id)
            } else {
                id.as_str() == team_id
            }
        })
        .count();
    if matching == 0 {
        return Ok(0.0);
    }
    Ok(if settings.team_attribution == "full" {
        1.0
    } else {
        matching as f64 / row.team_ids.len() as f64
    })
}

/// Whether a row's department is `departmentId` or (with `rollUp`) a department below it.
pub fn in_department(
    row: &crate::billing::ChargedRow,
    department_id: &str,
    directory: &crate::billing::Directory,
    roll_up: bool,
) -> IamResult<bool> {
    let Some(row_department) = row.department_id.as_deref().filter(|id| !id.is_empty()) else {
        return Ok(false);
    };
    if !roll_up {
        return Ok(row_department == department_id);
    }
    Ok(
        crate::departments::department_chain_of(&directory.departments, row_department)
            .iter()
            .any(|department| department.id == department_id),
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Budgets, credits, statements

/// What is still owed on an invoice: its total less payments and credit notes (never below 0).
pub fn amount_due(statement: &crate::billing::BillingStatement) -> IamResult<f64> {
    Ok(due_of(statement))
}

/// [`amount_due`] without the `Result`.
pub(crate) fn due_of(statement: &BillingStatement) -> f64 {
    if statement.status == "void" || statement.status == "draft" {
        return if statement.status == "draft" {
            statement.total_micros
        } else {
            0.0
        };
    }
    micros(js_max(
        0.0,
        statement.total_micros - paid_of(statement) - statement.credit_notes_micros.unwrap_or(0.0),
    ))
}

/// Payments received on an invoice; invoices marked paid before payments were recorded count as fully paid.
pub fn amount_paid(statement: &crate::billing::BillingStatement) -> IamResult<f64> {
    Ok(paid_of(statement))
}

/// [`amount_paid`] without the `Result`.
pub(crate) fn paid_of(statement: &BillingStatement) -> f64 {
    if let Some(paid) = statement.amount_paid_micros {
        return paid;
    }
    if statement.status == "paid" {
        statement.total_micros
    } else {
        0.0
    }
}

/// A subscription's state at an instant.
pub fn subscription_status(
    subscription: &crate::billing::BillingSubscription,
    now: f64,
) -> IamResult<String> {
    if subscription.ends_at.is_some_and(|ends_at| ends_at <= now) {
        return Ok("ended".to_owned());
    }
    if subscription
        .trial_ends_at
        .is_some_and(|trial_ends_at| trial_ends_at > now)
    {
        return Ok("trialing".to_owned());
    }
    Ok("active".to_owned())
}

/// Whether a redeemed coupon discounts an invoice for `period`: `once` until one invoice used it, `repeating` for
/// the invoices of `durationInMonths` months from the month it was redeemed, `forever` until removed.
pub fn discount_active(
    discount: &crate::billing::BillingDiscount,
    period: &str,
    time_zone: &str,
) -> IamResult<bool> {
    if discount.ended_at.is_some() {
        return Ok(false);
    }
    if discount.duration == "once" {
        return Ok(discount.applied_invoices == 0.0);
    }
    if discount.duration == "repeating" {
        let from = period_of(discount.redeemed_at, time_zone)?;
        let until = shift(&from, discount.duration_in_months.unwrap_or(1.0));
        return Ok(
            core_js::cmp_utf16(period, &from).is_ge() && core_js::cmp_utf16(period, &until).is_lt()
        );
    }
    Ok(true)
}

/// [`overlap_share`] without the `Result`.
pub(crate) fn overlap(start: f64, end: f64, from: f64, to: f64) -> f64 {
    let length = end - start;
    if length <= 0.0 {
        return 0.0;
    }
    let covered = js_max(0.0, js_min(end, to) - js_max(start, from));
    js_round((covered / length) * 10_000.0) / 10_000.0
}

/// The share (0-1, four decimals) of `[start, end)` that `[from, to)` covers.
pub fn overlap_share(start: f64, end: f64, from: f64, to: f64) -> IamResult<f64> {
    Ok(overlap(start, end, from, to))
}

/// Validates budget thresholds: 1-10 distinct percentages from 1 to 1000, ascending.
pub fn budget_thresholds(value: Option<&Value>) -> IamResult<Vec<f64>> {
    let Some(value) = value else {
        return Ok(vec![50.0, 80.0, 100.0]);
    };
    let items = match value {
        Value::Array(items) if !items.is_empty() && items.len() <= 10 => items,
        _ => {
            return Err(crate::js::invalid_input(
                "thresholds must list 1-10 percentages",
            ));
        }
    };
    // Forms send numbers as text ("50, 80, 100").
    let numeric = |item: &Value| -> Value {
        if let Value::String(text) = item {
            let trimmed = core_js::trim(text);
            if !trimmed.is_empty()
                && trimmed.len() <= 4
                && trimmed.bytes().all(|b| b.is_ascii_digit())
            {
                return number(core_js::string_to_number(trimmed));
            }
        }
        item.clone()
    };
    let mut thresholds: Vec<f64> = Vec::new();
    for item in items {
        let value = integer(Some(&numeric(item)), "thresholds", 1.0, 1000.0)?;
        if !thresholds.contains(&value) {
            thresholds.push(value);
        }
    }
    thresholds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Ok(thresholds)
}

/// Retention of a usage event recorded for `period`.
pub fn usage_expiry(period: &str, settings: &crate::billing::BillingSettings) -> IamResult<f64> {
    Ok(bounds_of(period, &settings.time_zone)?.end + settings.usage_retention_days * 86_400_000.0)
}

/// Statement content hash: what it bills, to whom, under which number (payment status is left out).
pub fn statement_hash(statement: &Value) -> IamResult<String> {
    let mut content = Map::new();
    for key in [
        "number",
        "period",
        "currency",
        "tenantId",
        "lines",
        "subtotalMicros",
        "creditsMicros",
        "totalMicros",
        "billTo",
        // Contract terms (absent on statements without them, so earlier hashes still verify).
        "discount",
        "commitment",
        "tax",
        "coupons",
        "billingReason",
    ] {
        if let Some(value) = statement.get(key) {
            content.insert(key.to_owned(), value.clone());
        }
    }
    Ok(hex::encode(Sha256::digest(
        core_js::stringify_object(&content).as_bytes(),
    )))
}

/// What `invoiceAmounts` turns into a total (its `credit` callback is the separate argument of
/// [`invoice_amounts_of`]).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InvoiceAmountsInput {
    pub subtotal_micros: f64,
    pub terms: Option<BillingTerms>,
    /// Whether the minimum commitment applies (the monthly invoice).
    pub commitment: bool,
    pub discounts: Vec<BillingDiscount>,
}

/// Turns an invoice's subtotal into its total, in order: the contract discount, the minimum-commitment true-up
/// (monthly invoices only), coupon discounts, credit, and tax on what is left. A negative balance (credit items
/// larger than the charges) comes back as `carryForwardMicros` for account credit, and the total stays 0.
///
/// JSON has no functions: the `credit` callback of the TypeScript input cannot travel in `input`, so this applies no
/// account credit (a callback answering 0). [`invoice_amounts_of`] takes the callback.
pub fn invoice_amounts(input: &Value) -> IamResult<Value> {
    let terms = match crate::js::defined(input.get("terms")) {
        Some(Value::Object(terms)) => Some(decode::<BillingTerms>(terms.clone())?),
        _ => None,
    };
    let discounts = match input.get("discounts") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Object(map) => decode::<BillingDiscount>(map.clone()),
                _ => Err(crate::js::internal_error()),
            })
            .collect::<IamResult<Vec<_>>>()?,
        _ => Vec::new(),
    };
    let amounts = InvoiceAmountsInput {
        subtotal_micros: input
            .get("subtotalMicros")
            .map(core_js::to_number)
            .unwrap_or(f64::NAN),
        terms,
        commitment: crate::js::truthy(input.get("commitment")),
        discounts,
    };
    Ok(invoice_amounts_of(&amounts, |_| 0.0))
}

/// [`invoice_amounts`] with the `credit` callback: given what is due, it applies account credit and answers how much.
pub fn invoice_amounts_of(
    input: &InvoiceAmountsInput,
    mut credit: impl FnMut(f64) -> f64,
) -> Value {
    let subtotal_micros = input.subtotal_micros;
    let terms = input.terms.as_ref();
    let discount_percent = terms.and_then(|terms| terms.discount_percent);
    let minimum = terms.and_then(|terms| terms.minimum_commitment_micros);
    let tax_rate = terms.and_then(|terms| terms.tax_rate_percent);
    let contract_micros = match discount_percent {
        Some(percent) if subtotal_micros > 0.0 => cents((subtotal_micros * percent) / 100.0),
        _ => 0.0,
    };
    let mut net = micros(subtotal_micros - contract_micros);
    let true_up_micros = match minimum {
        Some(minimum) if input.commitment => cents(js_max(0.0, minimum - net)),
        _ => 0.0,
    };
    net = micros(net + true_up_micros);
    let mut coupons: Vec<Value> = Vec::new();
    for discount in &input.discounts {
        if net <= 0.0 {
            break;
        }
        let amount = cents(js_min(
            net,
            match discount.percent_off {
                Some(percent) => (net * percent) / 100.0,
                None => discount.amount_off_micros.unwrap_or(0.0),
            },
        ));
        if amount <= 0.0 {
            continue;
        }
        let mut coupon = Map::new();
        coupon.insert("discountId".into(), json!(discount.id));
        coupon.insert("code".into(), json!(discount.code));
        coupon.insert("name".into(), json!(discount.name));
        coupon.insert("amountMicros".into(), number(amount));
        coupons.push(Value::Object(coupon));
        net = micros(net - amount);
    }
    let carry_forward_micros = if net < 0.0 { micros(-net) } else { 0.0 };
    let due = js_max(0.0, net);
    let credits_micros = if due > 0.0 {
        micros(js_min(due, credit(due)))
    } else {
        0.0
    };
    let taxable = micros(due - credits_micros);
    let tax_micros = match tax_rate {
        Some(rate) => cents((taxable * rate) / 100.0),
        None => 0.0,
    };
    let mut result = Map::new();
    if let Some(percent) = discount_percent {
        result.insert(
            "discount".into(),
            json!({ "percent": number(percent), "amountMicros": number(contract_micros) }),
        );
    }
    if let (true, Some(minimum)) = (input.commitment, minimum) {
        result.insert(
            "commitment".into(),
            json!({ "minimumMicros": number(minimum), "trueUpMicros": number(true_up_micros) }),
        );
    }
    if !coupons.is_empty() {
        result.insert("coupons".into(), Value::Array(coupons));
    }
    result.insert("creditsMicros".into(), number(credits_micros));
    if let Some(rate) = tax_rate {
        let mut tax = Map::new();
        tax.insert(
            "label".into(),
            json!(
                terms
                    .and_then(|terms| terms.tax_label.clone())
                    .unwrap_or_else(|| "Tax".to_owned())
            ),
        );
        tax.insert("ratePercent".into(), number(rate));
        tax.insert("amountMicros".into(), number(tax_micros));
        result.insert("tax".into(), Value::Object(tax));
    }
    result.insert("totalMicros".into(), number(micros(taxable + tax_micros)));
    result.insert("carryForwardMicros".into(), number(carry_forward_micros));
    Value::Object(result)
}
