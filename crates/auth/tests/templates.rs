//! Port of `tests/templates.test.ts`, the template checks of `tests/security-e15e8e-auth.test.ts`, and the
//! TypeScript renderings of every template (`fixtures/templates.json`, written by `fixtures/generate-templates.mjs`),
//! which the Rust renderer must reproduce exactly.

use better_iam_auth::templates::{
    AccountLink, BillingLink, CertificationLink, ClearancesLink, DelegationLink, GuestsLink,
    InvitationLink, MagicLink, PrivacyLink, RenderInput, TeamLink, TemplateLinks, TemplateOptions,
    ThreatsLink, TokenLink,
};
use better_iam_auth::{describe_user_agent, render_delivery_message};
use serde_json::{Map, Value, json};

fn site(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// The link builders of `generate-templates.mjs`.
fn fixture_links(mode: &str) -> TemplateLinks {
    let account = || -> Option<Box<dyn Fn(AccountLink) -> String + Send + Sync>> {
        Some(Box::new(|i: AccountLink| {
            format!(
                "https://app.example/account?tenant={}&site={}",
                i.tenant_id,
                site(&i.sign_in_url)
            )
        }))
    };
    match mode {
        "none" => TemplateLinks::default(),
        "account" => TemplateLinks {
            account: account(),
            ..Default::default()
        },
        _ => {
            let token_link =
                |name: &'static str| -> Option<Box<dyn Fn(TokenLink) -> String + Send + Sync>> {
                    Some(Box::new(move |i: TokenLink| {
                        format!(
                            "https://app.example/{name}?tenant={}&token={}&site={}",
                            i.tenant_id,
                            i.token,
                            site(&i.sign_in_url)
                        )
                    }))
                };
            TemplateLinks {
                invitation: Some(Box::new(|i: InvitationLink| {
                    format!(
                        "https://app.example/invitation?kind={}&tenant={}&token={}&site={}",
                        i.kind,
                        i.tenant_id,
                        i.token,
                        site(&i.sign_in_url)
                    )
                })),
                password_reset: token_link("passwordReset"),
                verify_email: token_link("verifyEmail"),
                email_change: token_link("emailChange"),
                magic_link: Some(Box::new(|i: MagicLink| {
                    format!(
                        "https://app.example/magicLink?tenant={}&token={}&to={}&site={}",
                        i.tenant_id,
                        i.token,
                        i.destination,
                        site(&i.sign_in_url)
                    )
                })),
                account: account(),
                certification: Some(Box::new(|i: CertificationLink| {
                    format!(
                        "https://app.example/certification?tenant={}&campaign={}&site={}",
                        i.tenant_id,
                        i.campaign_id,
                        site(&i.sign_in_url)
                    )
                })),
                delegation: Some(Box::new(|i: DelegationLink| {
                    format!(
                        "https://app.example/delegation?tenant={}&delegation={}&site={}",
                        i.tenant_id,
                        i.delegation_id,
                        site(&i.sign_in_url)
                    )
                })),
                team: Some(Box::new(|i: TeamLink| {
                    format!(
                        "https://app.example/team?tenant={}&team={}&site={}",
                        i.tenant_id,
                        i.team_id,
                        site(&i.sign_in_url)
                    )
                })),
                billing: Some(Box::new(|i: BillingLink| {
                    format!(
                        "https://app.example/billing?tenant={}&statement={}&site={}",
                        i.tenant_id,
                        i.statement_id.clone().unwrap_or_default(),
                        site(&i.sign_in_url)
                    )
                })),
                privacy: Some(Box::new(|i: PrivacyLink| {
                    format!(
                        "https://app.example/privacy?tenant={}&request={}&token={}&handler={}&site={}",
                        i.tenant_id,
                        i.request_id.clone().unwrap_or_default(),
                        i.token.clone().unwrap_or_else(|| "-".to_owned()),
                        i.handler
                            .map_or("-".to_owned(), |handler| handler.to_string()),
                        site(&i.sign_in_url)
                    )
                })),
                threats: Some(Box::new(|i: ThreatsLink| {
                    format!(
                        "https://app.example/threats?tenant={}&incident={}&site={}",
                        i.tenant_id,
                        i.incident_id.clone().unwrap_or_default(),
                        site(&i.sign_in_url)
                    )
                })),
                guest_invitation: token_link("guestInvitation"),
                guests: Some(Box::new(|i: GuestsLink| {
                    format!(
                        "https://app.example/guests?tenant={}&guest={}&site={}",
                        i.tenant_id,
                        i.guest_id.clone().unwrap_or_default(),
                        site(&i.sign_in_url)
                    )
                })),
                clearances: Some(Box::new(|i: ClearancesLink| {
                    format!(
                        "https://app.example/clearances?tenant={}&identity={}&site={}",
                        i.tenant_id,
                        i.identity_id.clone().unwrap_or_default(),
                        site(&i.sign_in_url)
                    )
                })),
            }
        }
    }
}

#[test]
fn renders_every_template_exactly_as_the_typescript_implementation() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/templates.json");
    let fixtures: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = fixtures["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 630);
    for (index, case) in cases.iter().enumerate() {
        let message = &case["message"];
        let input = RenderInput {
            template: message["template"].as_str().unwrap().to_owned(),
            to: message["to"].as_str().unwrap().to_owned(),
            payload: message["payload"].as_object().cloned().unwrap_or_default(),
            tenant_id: message
                .get("tenantId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            sign_in_url: message
                .get("signInUrl")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        let options = TemplateOptions {
            app_name: case["appName"].as_str().map(str::to_owned),
            links: fixture_links(case["links"].as_str().unwrap()),
        };
        let rendered = render_delivery_message(&input, &options);
        let label = format!("case {index} ({} / {})", input.template, case["links"]);
        match &case["rendered"] {
            Value::Null => assert!(rendered.is_none(), "{label}"),
            expected => {
                let rendered = rendered.unwrap_or_else(|| panic!("{label}: not rendered"));
                assert_eq!(
                    rendered.subject,
                    expected["subject"].as_str().unwrap(),
                    "{label} subject"
                );
                assert_eq!(
                    rendered.text,
                    expected["text"].as_str().unwrap(),
                    "{label} text"
                );
                assert_eq!(
                    rendered.html,
                    expected["html"].as_str().unwrap(),
                    "{label} html"
                );
            }
        }
    }
}

fn payload(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

fn render(
    template: &str,
    to: &str,
    tenant: Option<&str>,
    data: Value,
    options: &TemplateOptions,
) -> better_iam_auth::RenderedMessage {
    render_delivery_message(
        &RenderInput {
            template: template.to_owned(),
            to: to.to_owned(),
            payload: payload(data),
            tenant_id: tenant.map(str::to_owned),
            sign_in_url: None,
        },
        options,
    )
    .unwrap()
}

fn test_links() -> TemplateLinks {
    TemplateLinks {
        invitation: Some(Box::new(|i: InvitationLink| {
            format!(
                "https://app.example/join?kind={}&tenant={}&token={}",
                i.kind, i.tenant_id, i.token
            )
        })),
        password_reset: Some(Box::new(|i: TokenLink| {
            format!(
                "https://app.example/reset?tenant={}&token={}",
                i.tenant_id, i.token
            )
        })),
        verify_email: Some(Box::new(|i: TokenLink| {
            format!("https://app.example/verify?token={}", i.token)
        })),
        email_change: Some(Box::new(|i: TokenLink| {
            format!("https://app.example/email?token={}", i.token)
        })),
        magic_link: Some(Box::new(|i: MagicLink| {
            format!(
                "https://app.example/magic?token={}&to={}",
                i.token,
                better_iam_auth::util::encode_uri_component(&i.destination)
            )
        })),
        ..Default::default()
    }
}

#[test]
fn renders_every_built_in_template_with_links_escaping_payload_text_in_html() {
    let acme = TemplateOptions {
        app_name: Some("Acme Cloud".to_owned()),
        links: test_links(),
    };
    let invitation = render(
        "member-invitation",
        "alice@example.test",
        None,
        json!({ "token": "tok", "tenantId": "t1", "tenantName": "Acme <script>alert(1)</script>", "inviterName": "Owner \"O\"" }),
        &acme,
    );
    assert_eq!(
        invitation.subject,
        "Join Acme <script>alert(1)</script> on Acme Cloud"
    );
    assert!(
        invitation
            .text
            .contains("Owner \"O\" invited you to join Acme <script>alert(1)</script>.")
    );
    assert!(
        invitation.text.contains(
            "Accept invitation: https://app.example/join?kind=member&tenant=t1&token=tok"
        )
    );
    assert!(!invitation.html.contains("<script>"));
    assert!(invitation.html.contains("&lt;script&gt;"));
    assert!(
        invitation
            .html
            .contains("href=\"https://app.example/join?kind=member&amp;tenant=t1&amp;token=tok\"")
    );
    let with_links = TemplateOptions {
        app_name: None,
        links: test_links(),
    };
    let owner = render(
        "owner-invitation",
        "o@example.test",
        None,
        json!({ "token": "tok", "tenantId": "t1", "tenantName": "Acme" }),
        &with_links,
    );
    assert_eq!(owner.subject, "Set up Acme on Better IAM");
    assert!(owner.text.contains("kind=owner"));
    let reset = render(
        "password-reset",
        "a@example.test",
        None,
        json!({ "token": "r1", "tenantId": "t1" }),
        &with_links,
    );
    assert_eq!(reset.subject, "Reset your Better IAM password");
    assert!(
        reset
            .text
            .contains("https://app.example/reset?tenant=t1&token=r1")
    );
    assert!(reset.html.contains("Choose a new password"));
    for (template, needle) in [
        ("verify-email", "https://app.example/verify?token=v1"),
        ("email-change", "https://app.example/email?token=v1"),
        (
            "magic-link",
            "https://app.example/magic?token=v1&to=a%40example.test",
        ),
    ] {
        let rendered = render(
            template,
            "a@example.test",
            None,
            json!({ "token": "v1", "tenantId": "t1" }),
            &with_links,
        );
        assert!(rendered.text.contains(needle), "{template}");
        assert!(
            rendered.html.contains(&needle.replace('&', "&amp;")),
            "{template}"
        );
    }
    let plain = TemplateOptions::default();
    let code = render(
        "code",
        "+15550001",
        None,
        json!({ "token": "123456" }),
        &plain,
    );
    assert!(code.text.contains("Enter this code to sign in: 123456"));
    let mfa = render(
        "mfa-code",
        "a@example.test",
        None,
        json!({ "code": "654321" }),
        &plain,
    );
    assert_eq!(mfa.subject, "Your Better IAM verification code");
    assert!(mfa.text.contains("654321"));
    let alert = render(
        "new-sign-in",
        "a@example.test",
        None,
        json!({
            "method": "password",
            "time": "2026-09-22T00:00:00.000Z",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
            "ip": "203.0.113.7",
        }),
        &plain,
    );
    assert_eq!(alert.subject, "New sign-in to Better IAM");
    assert!(alert.text.contains("Chrome on Windows · 203.0.113.7"));
    assert!(alert.text.contains("Method: password."));
    let failures = render(
        "sign-in-failures",
        "a@example.test",
        None,
        json!({ "attempts": "5", "time": "2026-09-22T00:00:00.000Z", "ip": "198.51.100.9" }),
        &plain,
    );
    assert_eq!(
        failures.subject,
        "Failed sign-in attempts on your Better IAM account"
    );
    assert!(
        failures
            .text
            .contains("5 attempts to sign in to your account have failed")
    );
    assert!(failures.text.contains("the latest from 198.51.100.9"));
    assert!(failures.html.contains("Nobody has got in"));
    assert!(!failures.html.contains("href="));
    let account = TemplateOptions {
        app_name: None,
        links: TemplateLinks {
            account: Some(Box::new(|i: AccountLink| {
                format!("https://app.example.test/{}/account", i.tenant_id)
            })),
            ..Default::default()
        },
    };
    let linked = render(
        "new-sign-in",
        "a@example.test",
        Some("tenant-1"),
        json!({ "method": "password", "time": "2026-09-22T00:00:00.000Z" }),
        &account,
    );
    assert!(
        linked
            .text
            .contains("Review your account: https://app.example.test/tenant-1/account")
    );
    assert!(
        linked
            .html
            .contains("href=\"https://app.example.test/tenant-1/account\"")
    );
    let linked_failures = render(
        "sign-in-failures",
        "a@example.test",
        Some("tenant-1"),
        json!({ "attempts": "5", "time": "2026-09-22T00:00:00.000Z" }),
        &account,
    );
    assert!(
        linked_failures
            .html
            .contains("href=\"https://app.example.test/tenant-1/account\"")
    );
}

#[test]
fn falls_back_to_the_raw_token_without_link_builders_and_ignores_unknown_templates() {
    let plain = TemplateOptions::default();
    let reset = render(
        "password-reset",
        "a@example.test",
        None,
        json!({ "token": "raw-token" }),
        &plain,
    );
    assert!(reset.text.contains("Code: raw-token"));
    assert!(reset.html.contains("<code>raw-token</code>"));
    assert!(!reset.html.contains("href="));
    assert!(
        render_delivery_message(
            &RenderInput {
                template: "not-a-template".to_owned(),
                to: "a@example.test".to_owned(),
                ..Default::default()
            },
            &plain
        )
        .is_none()
    );
}

#[test]
fn renders_access_certification_reviews_and_reminders_with_a_review_link_or_the_account_page() {
    let options = TemplateOptions {
        app_name: Some("Acme IAM".to_owned()),
        links: TemplateLinks {
            certification: Some(Box::new(|i: CertificationLink| {
                format!(
                    "https://app.example/{}/certifications/{}",
                    i.tenant_id, i.campaign_id
                )
            })),
            account: Some(Box::new(|i: AccountLink| {
                format!("https://app.example/{}/account", i.tenant_id)
            })),
            ..Default::default()
        },
    };
    let review = render(
        "certification-review",
        "manager@example.test",
        Some("tenant-1"),
        json!({ "campaignId": "campaign-1", "campaignName": "Q3 <review>", "items": "3", "dueAt": "2026-10-01T00:00:00.000Z" }),
        &options,
    );
    assert_eq!(review.subject, "Review access: Q3 <review>");
    assert!(review.text.contains("review 3 access items in Q3 <review>"));
    assert!(
        review
            .text
            .contains("Please decide by 2026-10-01T00:00:00.000Z.")
    );
    assert!(
        review
            .text
            .contains("Review access: https://app.example/tenant-1/certifications/campaign-1")
    );
    assert!(review.html.contains("Q3 &lt;review&gt;"));
    assert!(!review.html.contains("<review>"));
    let account_only = TemplateOptions {
        app_name: None,
        links: TemplateLinks {
            account: Some(Box::new(|i: AccountLink| {
                format!("https://app.example/{}/account", i.tenant_id)
            })),
            ..Default::default()
        },
    };
    let reminder = render(
        "certification-reminder",
        "manager@example.test",
        Some("tenant-1"),
        json!({ "campaignId": "campaign-1", "campaignName": "Q3", "pending": "1" }),
        &account_only,
    );
    assert_eq!(reminder.subject, "Reminder: Q3 is waiting for you");
    assert!(
        reminder
            .text
            .contains("1 access item still needs your decision in Q3.")
    );
    assert!(
        reminder
            .text
            .contains("Review access: https://app.example/tenant-1/account")
    );
    let bare = render(
        "certification-review",
        "manager@example.test",
        None,
        json!({ "campaignName": "Q3", "items": "2" }),
        &TemplateOptions::default(),
    );
    assert!(!bare.html.contains("href="));
}

#[test]
fn never_quotes_the_attacker_chosen_user_agent_in_sign_in_notices() {
    let crafted =
        "Mozilla/5.0 Chrome/1 Safari/1 <a href=https://evil.example>reset your password here</a>";
    let rendered = render(
        "new-sign-in",
        "a@example.test",
        None,
        json!({ "userAgent": crafted, "method": "password", "time": "now" }),
        &TemplateOptions::default(),
    );
    assert!(!rendered.text.contains("evil.example"));
    assert!(!rendered.html.contains("evil.example"));
    assert_eq!(
        describe_user_agent(Some(crafted)).as_deref(),
        Some("Chrome")
    );
    assert_eq!(
        describe_user_agent(Some("curl/8")).as_deref(),
        Some("an unrecognized browser or app")
    );
    assert_eq!(describe_user_agent(None), None);
}

#[test]
fn keeps_subjects_on_one_line_whatever_names_they_interpolate() {
    let rendered = render(
        "member-invitation",
        "a@example.test",
        None,
        json!({ "tenantName": "Acme\r\nBcc: victim@example.test", "token": "t" }),
        &TemplateOptions::default(),
    );
    assert!(!rendered.subject.contains('\n') && !rendered.subject.contains('\r'));
}
