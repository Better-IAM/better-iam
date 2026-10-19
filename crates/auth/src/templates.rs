//! Subjects, plain text and HTML for the messages Better IAM queues (`templates.ts`). The rendered text is identical
//! to the TypeScript implementation's, so a mixed fleet sends the same emails whichever server queued them.

use better_iam_core::js;
use serde_json::{Map, Value};

use crate::js_date;
use crate::util::{js_string, truthy};

/// A message ready for an email or SMS provider (`RenderedMessage`). `html` is only meaningful for email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedMessage {
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// `invitation` link input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationLink {
    /// `owner` or `member`.
    pub kind: &'static str,
    pub tenant_id: String,
    pub token: String,
    pub sign_in_url: Option<String>,
}

/// The input of the token-carrying links (`passwordReset`, `verifyEmail`, `emailChange`, `guestInvitation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLink {
    pub tenant_id: String,
    pub token: String,
    pub sign_in_url: Option<String>,
}

/// `magicLink` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLink {
    pub tenant_id: String,
    pub token: String,
    pub destination: String,
    pub sign_in_url: Option<String>,
}

/// `account` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLink {
    pub tenant_id: String,
    pub sign_in_url: Option<String>,
}

/// `certification` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationLink {
    pub tenant_id: String,
    pub campaign_id: String,
    pub sign_in_url: Option<String>,
}

/// `delegation` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationLink {
    pub tenant_id: String,
    pub delegation_id: String,
    pub sign_in_url: Option<String>,
}

/// `team` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamLink {
    pub tenant_id: String,
    pub team_id: String,
    pub sign_in_url: Option<String>,
}

/// `billing` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingLink {
    pub tenant_id: String,
    pub statement_id: Option<String>,
    pub sign_in_url: Option<String>,
}

/// `privacy` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyLink {
    pub tenant_id: String,
    pub request_id: Option<String>,
    pub token: Option<String>,
    pub handler: Option<bool>,
    pub sign_in_url: Option<String>,
}

/// `threats` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatsLink {
    pub tenant_id: String,
    pub incident_id: Option<String>,
    pub sign_in_url: Option<String>,
}

/// `guests` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestsLink {
    pub tenant_id: String,
    pub guest_id: Option<String>,
    pub sign_in_url: Option<String>,
}

/// `clearances` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearancesLink {
    pub tenant_id: String,
    pub identity_id: Option<String>,
    pub sign_in_url: Option<String>,
}

type Builder<T> = Option<Box<dyn Fn(T) -> String + Send + Sync>>;

/// Builds the links your application serves for token-carrying templates (`TemplateLinks`); a missing builder falls
/// back to the raw token. `sign_in_url` is the organization's own sign-in address when the deployment has
/// organization addresses or regions.
#[derive(Default)]
pub struct TemplateLinks {
    pub invitation: Builder<InvitationLink>,
    pub password_reset: Builder<TokenLink>,
    pub verify_email: Builder<TokenLink>,
    pub email_change: Builder<TokenLink>,
    pub magic_link: Builder<MagicLink>,
    /// The person's account page (sessions, devices, security activity), used by security notices.
    pub account: Builder<AccountLink>,
    /// An access-certification campaign's review page; certification emails fall back to `account`.
    pub certification: Builder<CertificationLink>,
    /// Where a person decides on an AI agent's delegation request; falls back to `account`.
    pub delegation: Builder<DelegationLink>,
    /// A team's page; team emails fall back to `account`.
    pub team: Builder<TeamLink>,
    /// The billing page; billing emails fall back to `account`.
    pub billing: Builder<BillingLink>,
    /// Privacy links; privacy emails without a builder fall back to `account` (or show the confirmation code).
    pub privacy: Builder<PrivacyLink>,
    /// A security incident's page; threat alerts fall back to `account`.
    pub threats: Builder<ThreatsLink>,
    /// Where an invited guest accepts a guest invitation; without it the email shows the token.
    pub guest_invitation: Builder<TokenLink>,
    /// The guests page, or one guest's page; guest emails fall back to `account`.
    pub guests: Builder<GuestsLink>,
    /// The clearances page, or one person's clearance; clearance emails fall back to `account`.
    pub clearances: Builder<ClearancesLink>,
}

/// `TemplateOptions`.
#[derive(Default)]
pub struct TemplateOptions {
    /// Product name used in subjects and greetings (default "Better IAM").
    pub app_name: Option<String>,
    pub links: TemplateLinks,
}

/// The message to render: `Pick<DeliveryMessage, 'template' | 'payload' | 'to'> & { tenantId?, signInUrl? }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RenderInput {
    pub template: String,
    pub to: String,
    pub payload: Map<String, Value>,
    pub tenant_id: Option<String>,
    pub sign_in_url: Option<String>,
}

impl From<&crate::types::DeliveryMessage> for RenderInput {
    fn from(message: &crate::types::DeliveryMessage) -> Self {
        Self {
            template: message.template.clone(),
            to: message.to.clone(),
            payload: message.payload.clone(),
            tenant_id: Some(message.tenant_id.clone()),
            sign_in_url: message.sign_in_url.clone(),
        }
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// One line of text: control characters and line separators (which could break a mail header) become spaces.
fn one_line(value: &str) -> String {
    js::trim(&crate::validation::replace_control_characters(value)).to_owned()
}

/// `value.slice(0, max)` in UTF-16 code units.
fn slice(value: &str, max: usize) -> String {
    crate::outbox::truncate_utf16(value, max)
}

const BROWSERS: [(&str, &str); 8] = [
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("SamsungBrowser/", "Samsung Internet"),
    ("Firefox/", "Firefox"),
    ("FxiOS/", "Firefox"),
    ("CriOS/", "Chrome"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
];
const SYSTEMS: [(&str, &str); 8] = [
    ("Windows", "Windows"),
    ("iPhone", "iOS"),
    ("iPad", "iPadOS"),
    ("Android", "Android"),
    ("CrOS", "ChromeOS"),
    ("Macintosh", "macOS"),
    ("Mac OS X", "macOS"),
    ("Linux", "Linux"),
];

/// `describeUserAgent(userAgent)`: a short description of a User-Agent for security notices ("Chrome on
/// Windows"). The header is chosen by whoever sent the request, so it never reaches a message verbatim.
pub fn describe_user_agent(user_agent: Option<&str>) -> Option<String> {
    let user_agent = user_agent.filter(|value| !value.is_empty())?;
    let browser = BROWSERS
        .iter()
        .find(|(token, _)| user_agent.contains(token))
        .map(|(_, name)| *name);
    let system = SYSTEMS
        .iter()
        .find(|(token, _)| user_agent.contains(token))
        .map(|(_, name)| *name);
    Some(match (browser, system) {
        (Some(browser), Some(system)) => format!("{browser} on {system}"),
        (Some(browser), None) => browser.to_owned(),
        (None, Some(system)) => format!("a browser or app on {system}"),
        (None, None) => "an unrecognized browser or app".to_owned(),
    })
}

struct Button {
    href: String,
    label: String,
}

fn layout(app_name: &str, title: &str, paragraphs: &[String], action: Option<&Button>) -> String {
    let body: String = paragraphs
        .iter()
        .map(|paragraph| format!("<p style=\"margin:0 0 16px\">{paragraph}</p>"))
        .collect();
    let button = match action {
        Some(action) => format!(
            "<p style=\"margin:0 0 24px\"><a href=\"{href}\" style=\"display:inline-block;padding:10px 18px;background:#1d4ed8;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600\">{label}</a></p><p style=\"margin:0 0 16px;font-size:13px;color:#555\">Or paste this address into your browser:<br><span style=\"word-break:break-all\">{href}</span></p>",
            href = escape(&action.href),
            label = escape(&action.label)
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111\"><div style=\"max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px\"><h1 style=\"font-size:20px;margin:0 0 20px\">{}</h1>{body}{button}<p style=\"margin:24px 0 0;font-size:12px;color:#777\">{}</p></div></body></html>",
        escape(title),
        escape(app_name)
    )
}

/// The action of a message: a link, or the token to show when no link builder is configured.
struct Action {
    href: Option<String>,
    label: String,
    fallback_token: Option<String>,
}

fn action(href: Option<String>, label: &str) -> Option<Action> {
    Some(Action {
        href,
        label: label.to_owned(),
        fallback_token: None,
    })
}

fn token_action(href: Option<String>, label: &str, token: Option<String>) -> Option<Action> {
    Some(Action {
        href,
        label: label.to_owned(),
        fallback_token: token,
    })
}

/// A valid `Date`'s time value, or None for an invalid date.
fn valid_date(ms: f64) -> Option<f64> {
    let ms = js_date::time_clip(ms);
    (!ms.is_nan()).then_some(ms)
}

/// `Number(value) || fallback`.
fn number_or(value: Option<&Value>, fallback: f64) -> f64 {
    let n = match value {
        None => f64::NAN,
        Some(value) => js::to_number(value),
    };
    if n == 0.0 || n.is_nan() { fallback } else { n }
}

fn n(value: f64) -> String {
    js::number_to_string(value)
}

/// `renderDeliveryMessage(message, options)`: renders the messages Better IAM queues into a subject, plain text,
/// and HTML, so a delivery callback can hand them to any provider. None for templates it does not know (plugins,
/// newer features), which the callback should render itself.
pub fn render_delivery_message(
    message: &RenderInput,
    options: &TemplateOptions,
) -> Option<RenderedMessage> {
    let app_name = options
        .app_name
        .clone()
        .unwrap_or_else(|| "Better IAM".to_owned());
    let app_name = app_name.as_str();
    let links = &options.links;
    let payload = &message.payload;
    // `payload.key` (undefined and null are nullish).
    let raw = |key: &str| payload.get(key).filter(|value| !value.is_null());
    // `payload.key ?? fallback` as text.
    let p = |key: &str| raw(key).map(js_string);
    let or = |key: &str, fallback: &str| p(key).unwrap_or_else(|| fallback.to_owned());
    // `payload.key ? ... : ...`.
    let has = |key: &str| truthy(payload.get(key));
    let message_tenant = message.tenant_id.clone();
    let site = message.sign_in_url.clone().filter(|url| !url.is_empty());
    // Sign-in emails carry their tenant on the message rather than in the payload; invitations carry it in both.
    let link_tenant = p("tenantId")
        .or_else(|| message_tenant.clone())
        .unwrap_or_default();
    // `message.tenantId ?? payload.tenantId`, judged for truthiness.
    let tenant = message_tenant
        .clone()
        .or_else(|| p("tenantId"))
        .filter(|tenant| !tenant.is_empty());
    let account_href = |tenant_id: &str| {
        links.account.as_ref().map(|account| {
            account(AccountLink {
                tenant_id: tenant_id.to_owned(),
                sign_in_url: site.clone(),
            })
        })
    };
    // Security notices point at the account page when the application says where it lives.
    let account_action = || {
        message_tenant
            .as_deref()
            .filter(|tenant| !tenant.is_empty())
            .map(|tenant| Action {
                href: account_href(tenant),
                label: "Review your account".to_owned(),
                fallback_token: None,
            })
    };
    let compose = |subject: &str,
                   title: &str,
                   lines: Vec<String>,
                   action: Option<Action>|
     -> RenderedMessage {
        let mut text_lines = lines.clone();
        let mut html_paragraphs: Vec<String> = lines.iter().map(|line| escape(line)).collect();
        let mut button = None;
        if let Some(action) = action {
            match (
                action.href.filter(|href| !href.is_empty()),
                action.fallback_token.filter(|token| !token.is_empty()),
            ) {
                (Some(href), _) => {
                    text_lines.push(format!("{}: {href}", action.label));
                    button = Some(Button {
                        href,
                        label: action.label,
                    });
                }
                (None, Some(token)) => {
                    text_lines.push(format!("Code: {token}"));
                    html_paragraphs.push(format!("<code>{}</code>", escape(&token)));
                }
                (None, None) => {}
            }
        }
        text_lines.push(String::new());
        text_lines.push(app_name.to_owned());
        RenderedMessage {
            // Subjects interpolate names and other stored values; a line break there would inject mail headers.
            subject: one_line(subject),
            text: text_lines.join("\n"),
            html: layout(app_name, title, &html_paragraphs, button.as_ref()),
        }
    };
    let expiry = |minutes: u32| format!("This link expires in {minutes} minutes.");
    let token = || p("token");
    let token_or_empty = || p("token").unwrap_or_default();
    let template = message.template.as_str();
    let rendered = match template {
        "verify-email" => compose(
            &format!("Verify your email for {app_name}"),
            "Verify your email",
            vec![
                "Confirm that this address belongs to you.".to_owned(),
                "This link is valid for 24 hours.".to_owned(),
            ],
            token_action(
                links.verify_email.as_ref().map(|build| {
                    build(TokenLink {
                        tenant_id: link_tenant.clone(),
                        token: token_or_empty(),
                        sign_in_url: site.clone(),
                    })
                }),
                "Verify email",
                token(),
            ),
        ),
        "password-reset" => compose(
            &format!("Reset your {app_name} password"),
            "Reset your password",
            vec![
                "Someone asked to reset the password for this address. If it was not you, ignore this message."
                    .to_owned(),
                expiry(10),
            ],
            token_action(
                links.password_reset.as_ref().map(|build| {
                    build(TokenLink {
                        tenant_id: link_tenant.clone(),
                        token: token_or_empty(),
                        sign_in_url: site.clone(),
                    })
                }),
                "Choose a new password",
                token(),
            ),
        ),
        "email-change" => compose(
            &format!("Confirm your new {app_name} email"),
            "Confirm your new email address",
            vec![
                "Confirm that you want to sign in with this address from now on.".to_owned(),
                expiry(10),
            ],
            token_action(
                links.email_change.as_ref().map(|build| {
                    build(TokenLink {
                        tenant_id: link_tenant.clone(),
                        token: token_or_empty(),
                        sign_in_url: site.clone(),
                    })
                }),
                "Confirm address",
                token(),
            ),
        ),
        "magic-link" => compose(
            &format!("Sign in to {app_name}"),
            "Your sign-in link",
            vec![
                "Use the link below to sign in. Anyone with it can sign in as you, so do not forward it.".to_owned(),
                expiry(5),
            ],
            token_action(
                links.magic_link.as_ref().map(|build| {
                    build(MagicLink {
                        tenant_id: link_tenant.clone(),
                        token: token_or_empty(),
                        destination: message.to.clone(),
                        sign_in_url: site.clone(),
                    })
                }),
                "Sign in",
                token(),
            ),
        ),
        "code" => compose(
            &format!("Your {app_name} sign-in code"),
            "Your sign-in code",
            vec![
                format!("Enter this code to sign in: {}", token_or_empty()),
                "It expires in 5 minutes. If you did not request it, ignore this message.".to_owned(),
            ],
            None,
        ),
        "mfa-code" => compose(
            &format!("Your {app_name} verification code"),
            "Your verification code",
            vec![
                format!("Enter this code to finish signing in: {}", or("code", "")),
                "It expires in a few minutes. If you did not request it, change your password.".to_owned(),
            ],
            None,
        ),
        "new-sign-in" => {
            let where_ = [
                if has("label") {
                    Some(slice(&one_line(&or("label", "")), 80))
                } else {
                    None
                },
                describe_user_agent(p("userAgent").as_deref()),
                p("ip"),
            ]
            .into_iter()
            .flatten()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
            compose(
                &format!("New sign-in to {app_name}"),
                "New sign-in to your account",
                vec![
                    format!(
                        "Your account was just used to sign in from a device we had not seen before{}.",
                        if where_.is_empty() { String::new() } else { format!(": {where_}") }
                    ),
                    format!(
                        "Method: {}. Time: {}.",
                        or("method", "unknown"),
                        or("time", "unknown")
                    ),
                    "If this was you, no action is needed. If not, change your password and sign out of every device."
                        .to_owned(),
                ],
                account_action(),
            )
        }
        "sign-in-failures" => {
            let where_ = [describe_user_agent(p("userAgent").as_deref()), p("ip")]
                .into_iter()
                .flatten()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            compose(
                &format!("Failed sign-in attempts on your {app_name} account"),
                "Failed sign-in attempts",
                vec![
                    format!(
                        "{} attempts to sign in to your account have failed since your last sign-in{}.",
                        or("attempts", "Several"),
                        if where_.is_empty() { String::new() } else { format!(", the latest from {where_}") }
                    ),
                    format!("Time of the latest attempt: {}.", or("time", "unknown")),
                    "Nobody has got in: your password held. If this was not you, change your password anywhere else it is used, and review the security activity on your account page."
                        .to_owned(),
                ],
                account_action(),
            )
        }
        "certification-review" | "certification-reminder" => {
            let reminder = template == "certification-reminder";
            let campaign = or("campaignName", "An access review");
            let count = number_or(raw(if reminder { "pending" } else { "items" }), 0.0);
            let due = if has("dueAt") {
                format!(" Please decide by {}.", or("dueAt", ""))
            } else {
                String::new()
            };
            let href = match &tenant {
                Some(tenant_id) if has("campaignId") && links.certification.is_some() => {
                    links.certification.as_ref().map(|build| {
                        build(CertificationLink {
                            tenant_id: tenant_id.clone(),
                            campaign_id: or("campaignId", ""),
                            sign_in_url: site.clone(),
                        })
                    })
                }
                Some(tenant_id) => account_href(tenant_id),
                None => None,
            };
            compose(
                &if reminder {
                    format!("Reminder: {campaign} is waiting for you")
                } else {
                    format!("Review access: {campaign}")
                },
                if reminder { "Access review reminder" } else { "You have access to review" },
                vec![
                    if reminder {
                        format!(
                            "{} access {} your decision in {campaign}.{due}",
                            n(count),
                            if count == 1.0 { "item still needs" } else { "items still need" }
                        )
                    } else {
                        format!(
                            "You were asked to review {} access {} in {campaign}: keep what people still need and revoke the rest.{due}",
                            n(count),
                            if count == 1.0 { "item" } else { "items" }
                        )
                    },
                    "Undecided items may be kept or revoked automatically when the review closes.".to_owned(),
                ],
                action(href, "Review access"),
            )
        }
        "delegation-request" => {
            let agent = or("agentName", "An AI agent");
            let days = number_or(raw("days"), 0.0);
            let href = delegation_href(links, &tenant, has("delegationId"), &or("delegationId", ""), &site, &account_href);
            let mut lines = vec![
                format!(
                    "{agent}{} asks for permission to act on your behalf{}.",
                    if has("model") { format!(" ({})", or("model", "")) } else { String::new() },
                    if days != 0.0 {
                        format!(" for {} {}", n(days), if days == 1.0 { "day" } else { "days" })
                    } else {
                        String::new()
                    }
                ),
                format!(
                    "It asks for: {}. It can never do more than you can yourself.",
                    or("scopes", "a custom set of permissions")
                ),
            ];
            if has("reason") {
                lines.push(format!("Its reason: “{}”", or("reason", "")));
            }
            lines.push(
                "If you do not recognize this agent, deny the request. You can revoke a delegation at any time."
                    .to_owned(),
            );
            compose(
                &format!("{agent} asks to act on your behalf"),
                "An agent asks to act for you",
                lines,
                action(href, "Review the request"),
            )
        }
        "team-review-requested" => {
            let team = or("teamName", "your team");
            let href = team_href(links, &tenant, has("teamId"), &or("teamId", ""), &site, &account_href);
            let due = if has("dueAt") { valid_date(js_date::parse(&or("dueAt", ""))) } else { None };
            let mut lines = vec![format!(
                "An administrator asked the maintainers of {team} to confirm who still belongs{}: keep the people who still need the team's access, and remove the rest.",
                if has("memberCount") { format!(" ({} people)", or("memberCount", "")) } else { String::new() }
            )];
            if let Some(due) = due {
                lines.push(format!(
                    "Please decide by {}. {}",
                    js_date::to_utc_string(due),
                    if strict_eq(raw("onUndecided"), "remove") {
                        "People nobody decides on then leave the team."
                    } else {
                        "People nobody decides on then stay in the team."
                    }
                ));
            }
            if has("note") {
                lines.push(format!("Note: “{}”", or("note", "")));
            }
            compose(
                &format!("Review the members of {team}"),
                &format!("Who still belongs in {team}?"),
                lines,
                action(href, "Review the members"),
            )
        }
        "team-join-request" | "team-join-decided" => {
            let team = or("teamName", "a team");
            let href = team_href(links, &tenant, has("teamId"), &or("teamId", ""), &site, &account_href);
            if template == "team-join-request" {
                let who = or("requesterName", "Someone");
                let mut lines = vec![format!(
                    "{who}{} asks to join {team}. Joining gives them the access the team holds.",
                    if has("requesterEmail") { format!(" ({})", or("requesterEmail", "")) } else { String::new() }
                )];
                if has("justification") {
                    lines.push(format!("Their reason: “{}”", or("justification", "")));
                }
                lines.push("As a maintainer of the team you can approve or deny the request.".to_owned());
                compose(
                    &format!("{who} asks to join {team}"),
                    &format!("A request to join {team}"),
                    lines,
                    action(href, "Review the request"),
                )
            } else {
                let approved = strict_eq(raw("decision"), "approved");
                let mut lines = vec![if approved {
                    format!("Your request to join {team} was approved. You now have the access the team holds.")
                } else {
                    format!("Your request to join {team} was declined.")
                }];
                if has("note") {
                    lines.push(format!("Note from the maintainer: “{}”", or("note", "")));
                }
                compose(
                    &if approved {
                        format!("You joined {team}")
                    } else {
                        format!("Your request to join {team} was declined")
                    },
                    &if approved { format!("Welcome to {team}") } else { "Join request declined".to_owned() },
                    lines,
                    action(href, if approved { "Open the team" } else { "Review your account" }),
                )
            }
        }
        "delegation-confirmation" => {
            let agent = or("agentName", "An AI agent");
            let href = delegation_href(links, &tenant, has("delegationId"), &or("delegationId", ""), &site, &account_href);
            let mut lines = vec![format!(
                "{agent} is acting for you and wants to perform {} on {}. You asked to confirm actions like this one before it takes them.",
                or("action", "an action"),
                or("resource", "a resource")
            )];
            if has("reason") {
                lines.push(format!("Its reason: “{}”", or("reason", "")));
            }
            lines.push(format!(
                "The request expires in {} minutes. If you do not expect it, reject it and review the agent's access.",
                or("minutes", "30")
            ));
            compose(
                &format!("{agent} asks you to confirm an action"),
                "Confirm an action by your agent",
                lines,
                action(href, "Review the request"),
            )
        }
        "spend-alert" | "spend-anomaly" | "billing-statement" | "payment-reminder" => {
            let statement = template == "billing-statement" || template == "payment-reminder";
            let href = match &tenant {
                Some(tenant_id) => match &links.billing {
                    Some(build) => Some(build(BillingLink {
                        tenant_id: tenant_id.clone(),
                        statement_id: if statement && has("statementId") { p("statementId") } else { None },
                        sign_in_url: site.clone(),
                    })),
                    None => account_href(tenant_id),
                },
                None => None,
            };
            if template == "spend-anomaly" {
                let items: Vec<Value> = match js::parse(&or("items", "[]")) {
                    Ok(Value::Array(items)) => items,
                    _ => Vec::new(),
                };
                let count = number_or(raw("count"), items.len() as f64);
                let day = or("day", "yesterday");
                let mut lines = vec![format!(
                    "{} {} spent far more than usual on {day}:",
                    n(count),
                    if count == 1.0 { "person, team or meter" } else { "people, teams or meters" }
                )];
                for item in &items {
                    let field = |key: &str| {
                        item.get(key)
                            .filter(|value| !value.is_null())
                            .map(js_string)
                            .unwrap_or_default()
                    };
                    lines.push(format!("{}: {} (usually {} a day)", field("what"), field("spent"), field("usual")));
                }
                lines.push("If this was not expected, find out who or what is behind it before it adds up.".to_owned());
                compose(
                    &format!("Unusual spend at {} on {day}", or("tenantName", "your organization")),
                    "Unusual spend",
                    lines,
                    action(href, "Review spend"),
                )
            } else if template == "payment-reminder" {
                let overdue = strict_eq(raw("overdue"), "true");
                let days = number_or(raw("days"), 0.0).abs();
                let number = or("number", "your invoice");
                let plural = if days == 1.0 { "" } else { "s" };
                compose(
                    &if overdue {
                        format!("Invoice {number} is {} day{plural} overdue", n(days))
                    } else {
                        format!(
                            "Invoice {number} is due {}",
                            if days != 0.0 { format!("in {} day{plural}", n(days)) } else { "today".to_owned() }
                        )
                    },
                    if overdue { "Payment overdue" } else { "Payment reminder" },
                    vec![
                        format!(
                            "{} is still due on invoice {number} for {} ({}), due {}.",
                            or("amountDue", "An amount"),
                            or("tenantName", "your organization"),
                            or("period", ""),
                            or("dueAt", "")
                        )
                        .replacen(" ()", "", 1),
                        if overdue {
                            "Please pay it as soon as you can, or reply if you believe it is wrong.".to_owned()
                        } else {
                            "If you have already paid it, you can ignore this reminder.".to_owned()
                        },
                    ],
                    action(href, "View invoice"),
                )
            } else if statement {
                let organization = or("tenantName", "your organization");
                let subscription = strict_eq(raw("reason"), "subscription");
                let subject = collapse_whitespace(&format!(
                    "Your {app_name} statement {} for {}",
                    or("number", ""),
                    or("period", "last month")
                ));
                compose(
                    &subject,
                    js::trim(&format!("Statement {}", or("number", ""))),
                    vec![
                        if subscription {
                            format!(
                                "The first invoice of the new subscription for {organization} is ready: {} due by {}.",
                                or("total", "see the invoice"),
                                or("dueAt", "the due date")
                            )
                        } else {
                            format!(
                                "The statement for {organization} for {} is ready: {} due by {}.",
                                or("period", "last month"),
                                or("total", "see the statement"),
                                or("dueAt", "the due date")
                            )
                        },
                        format!("Subtotal {}, credits applied {}.", or("subtotal", ""), or("credits", "0")),
                    ],
                    action(href, "View statement"),
                )
            } else {
                let budget = or("budgetName", "A budget");
                let subject = or("subjectName", "The budget’s subject");
                let window = if has("windowStart") && has("windowEnd") && !loose_same(raw("windowStart"), raw("windowEnd")) {
                    format!(" ({} to {})", or("windowStart", ""), or("windowEnd", ""))
                } else if has("windowStart") {
                    format!(" ({})", or("windowStart", ""))
                } else {
                    String::new()
                };
                let forecast = strict_eq(raw("kind"), "forecast");
                let mut lines = vec![if forecast {
                    format!(
                        "At the current pace {subject} will spend about {} against the {} budget “{budget}”{window}.",
                        or("forecast", "more than planned"),
                        or("amount", "")
                    )
                } else {
                    format!(
                        "{subject} has spent {} of the {} budget “{budget}”{window}: {}%.",
                        or("spent", ""),
                        or("amount", ""),
                        p("percent").or_else(|| p("threshold")).unwrap_or_default()
                    )
                }];
                if !forecast && has("forecast") {
                    lines.push(format!("Projected by the end of the period: {}.", or("forecast", "")));
                }
                lines.push("Review spend by person, team and meter to see what drives it.".to_owned());
                compose(
                    &if forecast {
                        format!("{budget} is on track to exceed its budget")
                    } else {
                        format!("{budget} has reached {}% of its budget", or("threshold", "100"))
                    },
                    if forecast { "Spend forecast alert" } else { "Spend alert" },
                    lines,
                    action(href, "Review spend"),
                )
            }
        }
        "privacy-request-verify" | "privacy-request-received" | "privacy-request-update" | "privacy-request-due" => {
            let organization = or("tenantName", "the organization");
            let number = or("number", "your request");
            let asked = match p("type").unwrap_or_default().as_str() {
                "access" => "a copy of personal data",
                "portability" => "personal data in a portable format",
                "erasure" => "erasure of personal data",
                "rectification" => "correction of personal data",
                "restriction" => "restriction of processing",
                "objection" => "an objection to processing",
                "opt-out" => "an opt-out of sale or sharing",
                _ => "a privacy request",
            };
            let due = if has("dueAt") {
                valid_date(raw("dueAt").map_or(f64::NAN, js::to_number))
            } else {
                None
            };
            let due_text = due.map(js_date::to_utc_string);
            let link = |token: Option<String>, handler: Option<bool>| -> Option<String> {
                let tenant_id = tenant.as_ref()?;
                match &links.privacy {
                    Some(build) => Some(build(PrivacyLink {
                        tenant_id: tenant_id.clone(),
                        request_id: if has("requestId") { p("requestId") } else { None },
                        token,
                        handler,
                        sign_in_url: site.clone(),
                    })),
                    None if token.as_deref().is_some_and(|token| !token.is_empty()) => None,
                    None => account_href(tenant_id),
                }
            };
            match template {
                "privacy-request-verify" => {
                    let mut lines = vec![
                        format!(
                            "We received a request for {asked} from this address (reference {number}). Confirm it so {organization} can start handling it."
                        ),
                        "If you did not make this request, ignore this email: nothing happens until it is confirmed, and it lapses after seven days."
                            .to_owned(),
                    ];
                    if has("requestId") && links.privacy.is_none() {
                        lines.push(format!("Request ID: {}", or("requestId", "")));
                    }
                    compose(
                        &format!("Confirm your privacy request to {organization}"),
                        "Confirm your request",
                        lines,
                        token_action(link(Some(token_or_empty()), None), "Confirm request", token()),
                    )
                }
                "privacy-request-received" => {
                    let mut lines = vec![format!(
                        "{organization} received a request for {asked} ({number}{}{}).",
                        if has("regulation") { format!(", {}", or("regulation", "").to_uppercase()) } else { String::new() },
                        if has("channel") { format!(", via {}", or("channel", "")) } else { String::new() }
                    )];
                    if let Some(due_text) = &due_text {
                        lines.push(format!("It must be answered by {due_text}."));
                    }
                    compose(
                        &format!("New privacy request {number}: {asked}"),
                        "A privacy request needs handling",
                        lines,
                        action(link(None, Some(true)), "Open the request"),
                    )
                }
                "privacy-request-due" => {
                    let overdue = strict_eq(raw("overdue"), "true");
                    compose(
                        &if overdue {
                            format!("Privacy request {number} is overdue")
                        } else {
                            format!("Privacy request {number} is due soon")
                        },
                        if overdue { "Privacy request overdue" } else { "Privacy request due soon" },
                        vec![if overdue {
                            format!(
                                "The request for {asked} ({number}) at {organization} passed its deadline{}. Answer it now, or extend it if the regulation allows and you have not yet.",
                                due_text.as_ref().map(|text| format!(" on {text}")).unwrap_or_default()
                            )
                        } else {
                            format!(
                                "The request for {asked} ({number}) at {organization} must be answered by {}.",
                                due_text.clone().unwrap_or_else(|| "its deadline".to_owned())
                            )
                        }],
                        action(link(None, Some(true)), "Open the request"),
                    )
                }
                _ => {
                    let event = or("event", "completed");
                    let reason_text = |reason: &str| -> Option<&'static str> {
                        Some(match reason {
                            "unverified" => "we could not confirm who made it",
                            "unfounded" => "it is manifestly unfounded",
                            "excessive" => "it is excessive or repetitive",
                            "exempt" => "a legal exemption applies (for example a legal obligation to keep the data)",
                            "duplicate" => "it repeats a request already being handled",
                            "no-data" => "it holds no personal data about you",
                            "other" => "of the reason given by the organization",
                            _ => return None,
                        })
                    };
                    let lines = if event == "extended" {
                        let mut lines = vec![format!(
                            "{organization} needs more time to answer your request for {asked} ({number})."
                        )];
                        if let Some(due_text) = &due_text {
                            lines.push(format!("You will receive an answer by {due_text}."));
                        }
                        lines
                    } else if event == "rejected" {
                        vec![
                            format!(
                                "{organization} declined your request for {asked} ({number}) because {}.",
                                reason_text(&or("reason", "other"))
                                    .unwrap_or("of the reason given by the organization")
                            ),
                            "You may contact the organization’s privacy contact, or lodge a complaint with a data protection authority."
                                .to_owned(),
                        ]
                    } else {
                        let mut lines = vec![format!("{organization} completed your request for {asked} ({number}).")];
                        if strict_eq(raw("exportReady"), "true") {
                            lines.push(
                                "Your data is ready to download for a limited time from your privacy page after signing in."
                                    .to_owned(),
                            );
                        }
                        if strict_eq(raw("type"), "erasure") {
                            lines.push("Your personal data has been erased; this is the last message about it.".to_owned());
                        }
                        lines
                    };
                    let final_erasure = strict_eq(raw("type"), "erasure") && event == "completed";
                    compose(
                        &match event.as_str() {
                            "extended" => format!("More time needed for your privacy request {number}"),
                            "rejected" => format!("Your privacy request {number} was declined"),
                            _ => format!("Your privacy request {number} is complete"),
                        },
                        match event.as_str() {
                            "extended" => "Request extended",
                            "rejected" => "Request declined",
                            _ => "Request complete",
                        },
                        lines,
                        if final_erasure {
                            None
                        } else {
                            action(link(None, None), "View your privacy settings")
                        },
                    )
                }
            }
        }
        "threat-alert" => {
            let href = match &tenant {
                Some(tenant_id) => match &links.threats {
                    Some(build) => Some(build(ThreatsLink {
                        tenant_id: tenant_id.clone(),
                        incident_id: if has("incidentId") { p("incidentId") } else { None },
                        sign_in_url: site.clone(),
                    })),
                    None => account_href(tenant_id),
                },
                None => None,
            };
            let organization = or("tenantName", "your organization");
            let title = or("title", "Suspicious activity");
            let severity = or("severity", "unknown");
            let count = number_or(raw("detections"), 1.0);
            let mut first = severity.chars();
            let capitalized = match first.next() {
                Some(c) => format!("{}{}", c.to_uppercase(), first.as_str()),
                None => String::new(),
            };
            let mut lines = vec![format!(
                "{title}{} at {organization}.",
                if has("subject") { format!(" involving {}", or("subject", "")) } else { String::new() }
            )];
            if has("summary") {
                lines.push(or("summary", ""));
            }
            lines.push(format!(
                "Severity: {severity}. {} {} so far.",
                n(count),
                if count == 1.0 { "detection" } else { "detections" }
            ));
            lines.push(
                "If this activity was not expected, open the incident and respond: end the sessions, contain the account, or block the network."
                    .to_owned(),
            );
            compose(
                &format!("{capitalized} security incident at {organization}: {title}"),
                "Security incident",
                lines,
                action(href, "Review the incident"),
            )
        }
        "workflow-message" => {
            // Written by an administrator in a lifecycle workflow: plain text, one paragraph per line.
            let subject = slice(
                &p("subject").unwrap_or_else(|| {
                    format!("A message from {}", p("tenantName").unwrap_or_else(|| app_name.to_owned()))
                }),
                300,
            );
            let body = or("body", "");
            let lines: Vec<String> = body
                .split('\n')
                .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
                .take(200)
                .collect();
            compose(&subject, &subject, lines, account_action())
        }
        "guest-invitation" => {
            let tenant_name = or("tenantName", "an organization");
            let inviter = p("inviterName").filter(|_| has("inviterName"));
            let sponsor = p("sponsorName");
            let expires = if has("expiresAt") { valid_date(js_date::parse(&or("expiresAt", ""))) } else { None };
            let mut lines = vec![format!(
                "{} you to collaborate with {tenant_name} as a guest.{}",
                match &inviter {
                    Some(inviter) => format!("{inviter} invited"),
                    None => "You have been invited".to_owned(),
                },
                if has("sponsorName") && !loose_same(raw("sponsorName"), raw("inviterName")) {
                    format!(" {} sponsors your access.", sponsor.clone().unwrap_or_default())
                } else {
                    String::new()
                }
            )];
            if has("message") {
                lines.push(format!("Their message: “{}”", or("message", "")));
            }
            lines.push("Guest access is limited, and it ends unless your sponsor renews it.".to_owned());
            lines.push(format!(
                "The invitation is personal: accept it from the same email address{}.",
                expires.map(|at| format!(" by {}", js_date::to_utc_string(at))).unwrap_or_default()
            ));
            compose(
                &format!(
                    "{} to join {tenant_name} as a guest",
                    match &inviter {
                        Some(inviter) => format!("{inviter} invited you"),
                        None => "You are invited".to_owned(),
                    }
                ),
                &format!("Join {tenant_name} as a guest"),
                lines,
                token_action(
                    links.guest_invitation.as_ref().map(|build| {
                        build(TokenLink {
                            tenant_id: link_tenant.clone(),
                            token: token_or_empty(),
                            sign_in_url: site.clone(),
                        })
                    }),
                    "Accept invitation",
                    token(),
                ),
            )
        }
        "guest-review" | "guest-sponsor-missing" => {
            let href = match &tenant {
                Some(tenant_id) => match &links.guests {
                    Some(build) => Some(build(GuestsLink {
                        tenant_id: tenant_id.clone(),
                        guest_id: if has("guestId") { p("guestId") } else { None },
                        sign_in_url: site.clone(),
                    })),
                    None => account_href(tenant_id),
                },
                None => None,
            };
            let organization = or("tenantName", "your organization");
            let guest = or("guestName", "A guest");
            let who = format!(
                "{guest}{}",
                if has("guestEmail") { format!(" ({})", or("guestEmail", "")) } else { String::new() }
            );
            if template == "guest-sponsor-missing" {
                compose(
                    &format!("{guest} at {organization} has no sponsor"),
                    "A guest needs a sponsor",
                    vec![
                        format!(
                            "{} is no longer an active member of {organization}.",
                            if has("sponsorName") {
                                format!("{}, who sponsored {who},", or("sponsorName", ""))
                            } else {
                                format!("The person who sponsored {who}")
                            }
                        ),
                        "Assign the guest a new sponsor, or remove them if nobody vouches for them any more.".to_owned(),
                    ],
                    action(href, "Review the guest"),
                )
            } else {
                let ends = if has("expiresAt") { valid_date(js_date::parse(&or("expiresAt", ""))) } else { None };
                let review = if has("reviewDueAt") { valid_date(js_date::parse(&or("reviewDueAt", ""))) } else { None };
                let mut lines = vec![format!("You sponsor {who}, a guest at {organization}.")];
                if let Some(ends) = ends {
                    lines.push(format!(
                        "Their access ends on {} unless you renew it.",
                        js_date::to_utc_string(ends)
                    ));
                }
                if let Some(review) = review
                    && ends.is_none_or(|ends| review < ends) {
                        lines.push(format!(
                            "Please confirm by {} that they still need it.",
                            js_date::to_utc_string(review)
                        ));
                    }
                lines.push(
                    "Renew their access if they still need it; otherwise let it end, or ask an administrator to remove them."
                        .to_owned(),
                );
                compose(
                    &format!("Does {guest} still need access to {organization}?"),
                    "Review a guest you sponsor",
                    lines,
                    action(href, "Review the guest"),
                )
            }
        }
        "owner-invitation" | "member-invitation" => {
            let kind = if template == "owner-invitation" { "owner" } else { "member" };
            let tenant_name = or("tenantName", "an organization");
            let lead = if kind == "owner" {
                format!("You have been invited to set up {tenant_name} as its owner.")
            } else {
                format!(
                    "{} you to join {tenant_name}.",
                    if has("inviterName") {
                        format!("{} invited", or("inviterName", ""))
                    } else {
                        "You have been invited".to_owned()
                    }
                )
            };
            compose(
                &format!("{} {tenant_name} on {app_name}", if kind == "owner" { "Set up" } else { "Join" }),
                &if kind == "owner" { format!("Set up {tenant_name}") } else { format!("Join {tenant_name}") },
                vec![
                    lead,
                    "The invitation is personal and expires; accept it from the same email address.".to_owned(),
                ],
                token_action(
                    links.invitation.as_ref().map(|build| {
                        build(InvitationLink {
                            kind,
                            tenant_id: link_tenant.clone(),
                            token: token_or_empty(),
                            sign_in_url: site.clone(),
                        })
                    }),
                    "Accept invitation",
                    token(),
                ),
            )
        }
        "license-waiting" | "license-activated" => {
            let product = p("productName")
                .or_else(|| p("productKey"))
                .unwrap_or_else(|| "a license".to_owned());
            let organization = if has("tenantName") { or("tenantName", "") } else { "your organization".to_owned() };
            if template == "license-waiting" {
                compose(
                    &format!("You are on the waiting list for {product}"),
                    &format!("Waiting for a {product} seat"),
                    vec![
                        format!(
                            "You were given {product} at {organization}, but every seat is taken right now, so you are on the waiting list."
                        ),
                        "You get the next free seat automatically, and we will let you know when it is yours.".to_owned(),
                    ],
                    account_action(),
                )
            } else {
                compose(
                    &format!("Your {product} seat is ready"),
                    &format!("{product} is ready for you"),
                    vec![
                        format!("A seat of {product} at {organization} became free and is now yours."),
                        "You can use everything it includes right away.".to_owned(),
                    ],
                    account_action(),
                )
            }
        }
        // Security clearances. Mail passes through third-party providers, so these name the level only.
        "clearance-reminder" | "clearance-status" => {
            let organization = if has("tenantName") { or("tenantName", "") } else { "your organization".to_owned() };
            let level = if has("levelName") { format!(" (level: {})", or("levelName", "")) } else { String::new() };
            let valid = |key: &str| if has(key) { valid_date(js_date::parse(&or(key, ""))) } else { None };
            if template == "clearance-reminder" {
                let href = match &tenant {
                    Some(tenant_id) => match &links.clearances {
                        Some(build) => Some(build(ClearancesLink {
                            tenant_id: tenant_id.clone(),
                            identity_id: if has("identityId") { p("identityId") } else { None },
                            sign_in_url: site.clone(),
                        })),
                        None => account_href(tenant_id),
                    },
                    None => None,
                };
                let person = or("personName", "A person");
                let reinvestigation = valid("reinvestigationDue");
                let ends = valid("expiresAt");
                let interim = strict_eq(raw("status"), "interim");
                let mut lines = vec![format!(
                    "{person} holds {} security clearance at {organization}{level}.",
                    if interim { "an interim" } else { "a" }
                )];
                if let Some(at) = reinvestigation {
                    lines.push(format!(
                        "Their periodic reinvestigation is due on {}.",
                        js_date::to_utc_string(at)
                    ));
                }
                if let Some(at) = ends {
                    lines.push(format!(
                        "The {}clearance ends on {} unless it is renewed.",
                        if interim { "interim " } else { "" },
                        js_date::to_utc_string(at)
                    ));
                }
                lines.push("Review the clearance: schedule the investigation, renew or end it.".to_owned());
                compose(
                    &format!("Clearance review due at {organization}"),
                    "Clearance review due",
                    lines,
                    action(href, "Review the clearance"),
                )
            } else {
                let outcome = if strict_eq(raw("status"), "reinstated") {
                    "reinstated"
                } else if strict_eq(raw("status"), "revoked") {
                    "revoked"
                } else {
                    "suspended"
                };
                compose(
                    &format!("Your security clearance at {organization} was {outcome}"),
                    &format!("Clearance {outcome}"),
                    vec![
                        format!("Your security clearance at {organization}{level} was {outcome}."),
                        if outcome == "reinstated" {
                            "Access that depends on it is available again.".to_owned()
                        } else {
                            "Access to classified resources that depends on it has stopped. Your security officer can tell you more."
                                .to_owned()
                        },
                    ],
                    account_action(),
                )
            }
        }
        _ => return None,
    };
    Some(rendered)
}

/// `value === text` for a payload member.
fn strict_eq(value: Option<&Value>, text: &str) -> bool {
    value.and_then(Value::as_str) == Some(text)
}

/// `a !== b` negated, for two payload members (strings in practice).
fn loose_same(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => js::strict_equal(left, right),
        (None, None) => true,
        _ => false,
    }
}

/// `value.replace(/\s+/g, ' ')`.
fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for c in value.chars() {
        if js::is_js_whitespace(c) {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out
}

fn delegation_href(
    links: &TemplateLinks,
    tenant: &Option<String>,
    has_id: bool,
    id: &str,
    site: &Option<String>,
    account: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let tenant_id = tenant.as_ref()?;
    match &links.delegation {
        Some(build) if has_id => Some(build(DelegationLink {
            tenant_id: tenant_id.clone(),
            delegation_id: id.to_owned(),
            sign_in_url: site.clone(),
        })),
        _ => account(tenant_id),
    }
}

fn team_href(
    links: &TemplateLinks,
    tenant: &Option<String>,
    has_id: bool,
    id: &str,
    site: &Option<String>,
    account: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let tenant_id = tenant.as_ref()?;
    match &links.team {
        Some(build) if has_id => Some(build(TeamLink {
            tenant_id: tenant_id.clone(),
            team_id: id.to_owned(),
            sign_in_url: site.clone(),
        })),
        _ => account(tenant_id),
    }
}
