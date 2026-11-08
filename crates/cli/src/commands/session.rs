//! Saved sessions (`commands/session.ts`): login, logout, profiles, token.

use better_iam_core::js;
use serde_json::{Map, Value, json};

use super::members;
use crate::errors::{CliError, CliResult, usage_error};
use crate::framework::{
    ApiOptions, ArgSpec, CommandContext, CommandOutput, CommandSpec, CommandTarget, FlagSpec,
    define_command, describe_profile_target,
};
use crate::output::{OutputFormat, format_result};
use crate::paths::display;
use crate::profiles::StoredProfile;
use crate::transport::{
    ApiTransport, TransportMode, local_transport, remote_transport, same_endpoint,
};

async fn ask(
    context: &CommandContext,
    question: &str,
    hidden: bool,
    missing: &str,
) -> CliResult<String> {
    let Some(prompt) = &context.io.prompt else {
        return Err(CliError::hinted(
            "MISSING_ENV",
            missing,
            "Run it in a terminal, or set the variable.",
        ));
    };
    let answer = js::trim(&prompt(question.to_owned(), hidden).await?).to_owned();
    if answer.is_empty() {
        let label = question.trim_end();
        let label = label
            .strip_suffix(':')
            .or_else(|| label.strip_suffix('?'))
            .unwrap_or(label);
        return Err(usage_error(format!("{label} is required"), None));
    }
    Ok(answer)
}

/// The deployment a saved profile belongs to, as a transport carrying its token (never any other deployment).
fn profile_transport(
    context: &CommandContext,
    profile: &StoredProfile,
) -> CliResult<Option<ApiTransport>> {
    if let Some(url) = &profile.url {
        return remote_transport(url, Some(&profile.token), context.io.fetch.clone()).map(Some);
    }
    if let Some(config) = &profile.config {
        return Ok(Some(local_transport(
            context.open(Some(config))?,
            config,
            Some(&profile.token),
        )));
    }
    if profile.env_config == Some(true) {
        return Ok(Some(local_transport(
            context.open(None)?,
            "BETTER_IAM_DATABASE_URL",
            Some(&profile.token),
        )));
    }
    Ok(None)
}

/// Where this command's calls go, in the form a profile records it (`url`, `config`, or `envConfig`).
#[derive(Debug, Clone, Default, PartialEq)]
struct ProfileTarget {
    url: Option<String>,
    config: Option<String>,
    env_config: bool,
}

impl ProfileTarget {
    fn insert_into(&self, map: &mut Map<String, Value>) {
        if let Some(url) = &self.url {
            map.insert("url".into(), Value::String(url.clone()));
        } else if let Some(config) = &self.config {
            map.insert("config".into(), Value::String(config.clone()));
        } else if self.env_config {
            map.insert("envConfig".into(), Value::Bool(true));
        }
    }
}

fn target_of(context: &CommandContext, transport: &ApiTransport) -> CliResult<ProfileTarget> {
    if transport.mode == TransportMode::Remote {
        return Ok(ProfileTarget {
            url: Some(transport.target.clone()),
            ..ProfileTarget::default()
        });
    }
    Ok(match context.config_path()? {
        Some(where_) => ProfileTarget {
            config: Some(display(&where_.path)),
            ..ProfileTarget::default()
        },
        None => ProfileTarget {
            env_config: true,
            ..ProfileTarget::default()
        },
    })
}

fn same_target(profile: &StoredProfile, target: &ProfileTarget) -> bool {
    if let Some(url) = &target.url {
        return profile
            .url
            .as_deref()
            .is_some_and(|saved| same_endpoint(saved, url));
    }
    if let Some(config) = &target.config {
        return profile.config.as_deref() == Some(config.as_str());
    }
    profile.env_config == Some(true) && profile.url.is_none() && profile.config.is_none()
}

fn iso(ms: f64) -> Value {
    js::iso_string(ms).map_or(Value::Null, Value::String)
}

async fn login(context: std::sync::Arc<CommandContext>) -> CliResult<Option<Value>> {
    let flags = &context.flags;
    let anonymous = context.api(ApiOptions {
        anonymous: true,
        token: None,
    })?;
    // Refuse before signing in, so a new session never silently replaces one saved for another deployment.
    let where_ = target_of(&context, &anonymous)?;
    let profiles = &context.profiles;
    let name = profiles.current_name(flags.string("profile"))?;
    let existing = profiles.get(&name)?;
    if let Some(existing) = &existing
        && flags.string("profile").is_none()
        && !same_target(existing, &where_)
    {
        return Err(CliError::hinted(
            "PROFILE_IN_USE",
            format!(
                "Profile {name} holds a session for {}",
                describe_profile_target(existing)
            ),
            "Pass --profile NAME to save this session under another name, or run better-iam logout first.",
        ));
    }
    let token: String;
    let mut signed_in_email: Option<String> = None;
    if flags.boolean("with-token") {
        let Some(stdin) = &context.io.stdin else {
            return Err(usage_error(
                "--with-token reads the token from standard input",
                None,
            ));
        };
        token = js::trim(&stdin().await?).to_owned();
        if token.is_empty() {
            return Err(usage_error("Standard input held no token", None));
        }
    } else {
        // --org is always typed on the command line, so it wins over a BETTER_IAM_TENANT default.
        let mut tenant_id = if flags.string("org").is_some() {
            None
        } else {
            flags.string("tenant").map(str::to_owned)
        };
        if tenant_id.is_none() {
            let slug = match flags.string("org") {
                Some(slug) => slug.to_owned(),
                None => {
                    ask(
                        &context,
                        "Organization (slug): ",
                        false,
                        "Pass --tenant ID or --org SLUG",
                    )
                    .await?
                }
            };
            let found = anonymous
                .call("tenants/lookup", members(json!({ "slug": slug })))
                .await?;
            tenant_id = Some(better_iam_server::js::js_string(found.get("tenantId")));
        }
        let tenant_id = tenant_id.unwrap_or_default();
        let email = match flags.string("email") {
            Some(email) => email.to_owned(),
            None => {
                ask(
                    &context,
                    "Email: ",
                    false,
                    "Pass --email or set BETTER_IAM_EMAIL",
                )
                .await?
            }
        };
        signed_in_email = Some(email.clone());
        let password = match context
            .env
            .get("BETTER_IAM_PASSWORD")
            .filter(|value| !value.is_empty())
        {
            Some(password) => password.clone(),
            None => {
                ask(
                    &context,
                    "Password: ",
                    true,
                    "Set BETTER_IAM_PASSWORD (passwords are never flags)",
                )
                .await?
            }
        };
        let mut result = anonymous
            .call(
                "auth/signIn",
                members(json!({ "tenantId": tenant_id, "email": email, "password": password })),
            )
            .await?;
        if result.get("mfaRequired") == Some(&Value::Bool(true)) {
            let challenge = better_iam_server::js::js_string(result.get("challenge"));
            let email_code_available = result.get("emailCodeAvailable") == Some(&Value::Bool(true));
            if flags.boolean("email-code") {
                if !email_code_available {
                    return Err(CliError::new(
                        "MFA_EMAIL_UNAVAILABLE",
                        "This organization does not offer emailed codes",
                        None,
                    ));
                }
                anonymous
                    .call(
                        "auth/requestMfaCode",
                        members(json!({ "tenantId": tenant_id, "challenge": challenge })),
                    )
                    .await?;
                context.note(&format!("A one-time code was sent to {email}."));
            } else if result.get("enrollmentRequired") == Some(&Value::Bool(true)) {
                return Err(CliError::hinted(
                    "MFA_ENROLLMENT_REQUIRED",
                    "This account must enroll an authenticator before it can sign in",
                    if email_code_available {
                        "Enroll one in the console, or pass --email-code to receive a one-time code."
                    } else {
                        "Enroll one in the console first."
                    },
                ));
            }
            let code = match context
                .env
                .get("BETTER_IAM_MFA_CODE")
                .filter(|value| !value.is_empty())
            {
                Some(code) => code.clone(),
                None => {
                    ask(
                        &context,
                        if flags.boolean("email-code") {
                            "Emailed code: "
                        } else {
                            "Authenticator code: "
                        },
                        false,
                        "Set BETTER_IAM_MFA_CODE",
                    )
                    .await?
                }
            };
            result = anonymous
                .call(
                    "auth/verifyMfa",
                    members(json!({ "tenantId": tenant_id, "challenge": challenge, "code": code })),
                )
                .await?;
        }
        match result
            .get("token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
        {
            Some(issued) => token = issued.to_owned(),
            None => {
                return Err(CliError::new(
                    "SIGN_IN_INCOMPLETE",
                    "Sign-in did not return a session",
                    None,
                ));
            }
        }
    }
    let transport = context.api(ApiOptions {
        anonymous: false,
        token: Some(token.clone()),
    })?;
    let caller = transport.call("sts/getCallerIdentity", None).await?;
    let expires_at = caller.get("expiresAt").and_then(js::as_number);
    let text = |key: &str| caller.get(key).and_then(Value::as_str).map(str::to_owned);
    profiles.save(
        &name,
        &StoredProfile {
            url: where_.url.clone(),
            config: where_.config.clone(),
            env_config: where_.env_config.then_some(true),
            tenant_id: text("tenantId"),
            identity_id: text("identityId"),
            email: signed_in_email,
            kind: text("sessionKind"),
            token,
            expires_at,
            saved_at: js::system_now_ms(),
        },
        true,
    )?;
    let mut result = Map::new();
    result.insert("profile".into(), Value::String(name));
    where_.insert_into(&mut result);
    result.insert(
        "tenantId".into(),
        caller.get("tenantId").cloned().unwrap_or(Value::Null),
    );
    result.insert(
        "identityId".into(),
        caller.get("identityId").cloned().unwrap_or(Value::Null),
    );
    if let Some(expires_at) = expires_at {
        result.insert("expiresAt".into(), iso(expires_at));
    }
    result.insert(
        "credentials".into(),
        profiles
            .path
            .as_ref()
            .map_or(Value::Null, |path| Value::String(display(path))),
    );
    Ok(Some(Value::Object(result)))
}

pub fn session_commands() -> Vec<CommandSpec> {
    vec![
        define_command("login", "Sign in once and save the session for later commands", login)
            .group("Session")
            .description(
                "login signs in with an email and password (and an authenticator or emailed code when MFA is required) and saves the session in the credentials file as a profile (--profile, default the current profile or \"default\"; a profile that holds a session for another deployment is only replaced when named with --profile), so later token commands need no BETTER_IAM_TOKEN. The password comes from BETTER_IAM_PASSWORD or a hidden prompt and the code from BETTER_IAM_MFA_CODE or a prompt, never from flags. --with-token saves a token read from standard input instead (an API key for CI, or a session from elsewhere) after checking it. The profile remembers the server (--url) or configuration it was created with, and --tenant/--org sets the default tenant of later commands.",
            )
            .usage(
                "better-iam login [--config better-iam.json | --url URL] [--tenant TENANT_ID | --org SLUG] [--email EMAIL] [--email-code] [--with-token] [--profile NAME]",
            )
            .target(CommandTarget::Token)
            .flag(
                "tenant",
                FlagSpec::string("Organization to sign in to").value("TENANT_ID").env("BETTER_IAM_TENANT"),
            )
            .flag("org", FlagSpec::string("Organization to sign in to, by its slug").value("SLUG"))
            .flag(
                "email",
                FlagSpec::string("Account email (prompted when absent)").value("EMAIL").env("BETTER_IAM_EMAIL"),
            )
            .flag(
                "email-code",
                FlagSpec::boolean("Email a one-time code for MFA instead of using an authenticator"),
            )
            .flag(
                "with-token",
                FlagSpec::boolean("Save a token read from standard input instead of signing in"),
            )
            .examples(&[
                "better-iam login --url https://iam.example.com --org acme --email me@acme.test",
                "echo \"$API_KEY\" | better-iam login --with-token --url https://iam.example.com --profile ci",
            ])
            // Only flags typed on the command line conflict; BETTER_IAM_TENANT / BETTER_IAM_EMAIL are defaults that
            // yield.
            .validate(|_, _, explicit| {
                if explicit.contains("tenant") && explicit.contains("org") {
                    return Err(usage_error("Give --tenant or --org, not both", None));
                }
                if explicit.contains("with-token")
                    && ["tenant", "org", "email", "email-code"].iter().any(|name| explicit.contains(*name))
                {
                    return Err(usage_error(
                        "--with-token takes no sign-in flags (the token names its tenant)",
                        None,
                    ));
                }
                Ok(())
            }),
        define_command("logout", "Sign out and forget a saved session", |context| async move {
            let profiles = &context.profiles;
            let name = profiles.current_name(context.flags.string("profile"))?;
            let Some(saved) = profiles.get(&name)? else {
                return Err(CliError::hinted(
                    "NOT_FOUND",
                    format!("No saved session named {name}"),
                    "Run better-iam profiles to list them.",
                ));
            };
            let mut revoked = false;
            if saved.kind.as_deref().is_none_or(|kind| kind.is_empty() || kind == "user") {
                // An expired or already revoked session is gone either way.
                if let Ok(Some(transport)) = profile_transport(&context, &saved)
                    && transport.call("auth/signOut", None).await.is_ok()
                {
                    revoked = true;
                }
            }
            profiles.remove(&name)?;
            Ok(Some(json!({ "profile": name, "revoked": revoked, "forgotten": true })))
        })
        .group("Session")
        .description(
            "logout signs a saved user session out on the server (best effort; API keys and other machine credentials saved with --with-token are only forgotten, never revoked) and removes the profile from the credentials file.",
        )
        .target(CommandTarget::Token),
        define_command("profiles", "List saved sessions, or choose or remove one", |context| async move {
            let flags = &context.flags;
            let profiles = &context.profiles;
            let action = context.args.first().cloned();
            let name = context.args.get(1).cloned();
            let Some(action) = action else {
                let list: Vec<Value> = profiles
                    .list(flags.string("profile"))?
                    .into_iter()
                    .map(|mut entry| {
                        if let Value::Object(map) = &mut entry {
                            if let Some(expires_at) =
                                map.get("expiresAt").and_then(js::as_number).filter(|value| *value != 0.0)
                            {
                                map.insert("expiresAt".into(), iso(expires_at));
                            }
                            let saved_at = map.get("savedAt").and_then(js::as_number).unwrap_or(f64::NAN);
                            map.insert("savedAt".into(), iso(saved_at));
                        }
                        entry
                    })
                    .collect();
                (context.io.out)(&format_result(
                    &Value::Array(list),
                    Some(flags.format().unwrap_or(OutputFormat::Table)),
                    flags.query(),
                )?);
                return Ok(None);
            };
            let Some(name) = name.filter(|_| action == "use" || action == "remove") else {
                return Err(usage_error(
                    "Use: better-iam profiles, profiles use NAME, or profiles remove NAME",
                    None,
                ));
            };
            if action == "use" {
                profiles.use_profile(&name)?;
                return Ok(Some(json!({ "current": name })));
            }
            if !profiles.remove(&name)? {
                return Err(CliError::new("NOT_FOUND", format!("No saved profile named {name}"), None));
            }
            Ok(Some(json!({ "removed": name })))
        })
        .group("Session")
        .description(
            "profiles lists the sessions saved by login (never their tokens) and marks the current one; profiles use NAME makes NAME current, and profiles remove NAME forgets one without signing it out.",
        )
        .usage("better-iam profiles [use NAME | remove NAME]")
        .arg(ArgSpec::new("action", "use or remove"))
        .arg(ArgSpec::new("name", "The profile"))
        .flag(
            "profile",
            FlagSpec::string("Treat NAME as current")
                .value("NAME")
                .env("BETTER_IAM_PROFILE")
                .hidden(),
        ),
        define_command("token", "Print the token commands act as, for scripts", |context| async move {
            Ok(Some(Value::String(context.token()?)))
        })
        .group("Session")
        .description(
            "token prints the bearer token token commands would use (BETTER_IAM_TOKEN, else the saved profile's), for scripts and other tools: export BETTER_IAM_TOKEN=$(better-iam token). It is a secret; do not log it.",
        )
        .target(CommandTarget::Token)
        .output(CommandOutput::Text),
    ]
}
