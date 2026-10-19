//! Deployment-wide password screening; tenant rules (`TenantAuthPolicy.password*`) add to it (`password-policy.ts`).

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use better_iam_core::{IamError, IamResult, TenantAuthPolicy, js};
use futures::future::BoxFuture;
use regex::Regex;
use sha1::{Digest, Sha1};

/// The identity fields a custom password rule sees (`Pick<Identity, 'id' | 'email' | 'name'>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordIdentity {
    pub id: String,
    pub email: Option<String>,
    pub name: String,
}

/// The context of a custom password rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCheckContext {
    pub tenant_id: String,
    pub identity: Option<PasswordIdentity>,
}

/// `isBreached(password)`: true when the password appears in a breach corpus.
pub type BreachFn = Arc<dyn Fn(String) -> BoxFuture<'static, IamResult<bool>> + Send + Sync>;
/// `check(password, context)`: a message to reject the password, or None (or an empty message) to accept it.
pub type PasswordCheckFn = Arc<
    dyn Fn(String, PasswordCheckContext) -> BoxFuture<'static, IamResult<Option<String>>>
        + Send
        + Sync,
>;

/// Deployment-wide password screening (`PasswordPolicyOptions`).
#[derive(Clone, Default)]
pub struct PasswordPolicyOptions {
    /// Rejects well-known, keyboard-walk, sequential and low-variety passwords (default true).
    pub block_common_passwords: Option<bool>,
    /// Returns true when the password appears in a breach corpus; [`pwned_passwords`] provides a k-anonymity Have I
    /// Been Pwned client.
    pub is_breached: Option<BreachFn>,
    /// Custom rule.
    pub check: Option<PasswordCheckFn>,
}

const COMMON: [&str; 42] = [
    "password1234",
    "password12345",
    "password123456",
    "passw0rd1234",
    "p@ssw0rd1234",
    "p@ssword1234",
    "password!123",
    "passwordpassword",
    "iloveyou1234",
    "letmein12345",
    "welcome12345",
    "welcome123456",
    "changeme1234",
    "changeme12345",
    "administrator",
    "admin1234567",
    "adminadmin123",
    "football1234",
    "baseball1234",
    "princess1234",
    "sunshine1234",
    "superman1234",
    "trustno11234",
    "monkey123456",
    "dragon123456",
    "master123456",
    "correcthorsebatterystaple",
    "correct horse battery staple",
    "thequickbrownfox",
    "letmeinletmein",
    "secretpassword",
    "mypassword123",
    "default12345",
    "computer1234",
    "internet1234",
    "whatever1234",
    "starwars1234",
    "pokemon12345",
    "summer2024!!",
    "winter2024!!",
    "spring2025!!",
    "autumn2025!!",
];

const SEQUENCES: [&str; 7] = [
    "01234567890123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnm",
    "qwertzuiopasdfghjklyxcvbnm",
    "azertyuiopqsdfghjklmwxcvbn",
    "1qaz2wsx3edc4rfv5tgb6yhn",
    "!@#$%^&*()_+",
];

/// `characterClasses(password)`: lowercase, uppercase, digit, and everything else.
pub fn character_classes(password: &str) -> usize {
    [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|present| **present)
    .count()
}

/// `isCommonPassword(password)`: the built-in weak-password screen (common passwords, keyboard walks and sequences,
/// and low variety).
pub fn is_common_password(password: &str) -> bool {
    let lower = js::to_lower(password);
    let stripped: String = lower
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == ' ')
        .collect();
    if COMMON.contains(&lower.as_str()) || COMMON.contains(&stripped.as_str()) {
        return true;
    }
    if lower.chars().collect::<HashSet<char>>().len() < 5 {
        return true;
    }
    let length = js::utf16_len(&lower);
    for sequence in SEQUENCES {
        let count = (length * 2).div_ceil(sequence.len()) + 1;
        let forward = sequence.repeat(count);
        let reversed: String = forward.chars().rev().collect();
        if forward.contains(&lower) || reversed.contains(&lower) {
            return true;
        }
    }
    false
}

static NON_WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^\p{L}\p{N}]+").expect("a valid pattern"));

/// Pieces of the identity (email local part, name words) at least four characters long.
fn personal_tokens(email: Option<&str>, name: Option<&str>) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut add = |token: String| {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    };
    if let Some(local) = email
        .and_then(|email| email.split('@').next())
        .map(js::to_lower)
        && !local.is_empty()
    {
        add(local.clone());
        for part in local.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())) {
            add(part.to_owned());
        }
    }
    if let Some(name) = name {
        for part in NON_WORD.split(&js::to_lower(name)) {
            add(part.to_owned());
        }
    }
    tokens
        .into_iter()
        .filter(|token| js::utf16_len(token) >= 4)
        .collect()
}

/// The identity fields the synchronous rules look at (`Pick<Identity, 'email' | 'name'>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonalInfo<'a> {
    pub email: Option<&'a str>,
    pub name: Option<&'a str>,
}

/// `assertPasswordRules`: the synchronous rules (tenant length, character classes, personal information, the
/// built-in screen). History, breach, and custom checks run in the auth service.
pub fn assert_password_rules(
    password: &str,
    policy: Option<&TenantAuthPolicy>,
    options: Option<&PasswordPolicyOptions>,
    identity: Option<PersonalInfo<'_>>,
) -> IamResult<()> {
    if let Some(minimum) = policy.and_then(|policy| policy.min_password_length)
        && (js::utf16_len(password) as f64) < minimum
    {
        return Err(IamError::new(
            "WEAK_PASSWORD",
            format!(
                "Password must contain at least {} characters in this organization",
                js::number_to_string(minimum)
            ),
        ));
    }
    if let Some(classes) = policy.and_then(|policy| policy.password_min_classes)
        && (character_classes(password) as f64) < classes
    {
        return Err(IamError::new(
            "WEAK_PASSWORD",
            format!(
                "Password must mix at least {} of: lowercase, uppercase, digits, symbols",
                js::number_to_string(classes)
            ),
        ));
    }
    if policy.and_then(|policy| policy.password_reject_personal_info) == Some(true)
        && let Some(identity) = identity
    {
        let lower = js::to_lower(password);
        if personal_tokens(identity.email, identity.name)
            .iter()
            .any(|token| lower.contains(token.as_str()))
        {
            return Err(IamError::new(
                "WEAK_PASSWORD",
                "Password must not contain your name or email address",
            ));
        }
    }
    if options
        .and_then(|options| options.block_common_passwords)
        .unwrap_or(true)
        && is_common_password(password)
    {
        return Err(IamError::new(
            "WEAK_PASSWORD",
            "Password is too common or predictable",
        ));
    }
    Ok(())
}

/// One HTTP GET a [`pwned_passwords`] client makes: URL and headers; answers the status and the body text.
pub type PwnedFetchFn = Arc<
    dyn Fn(String, Vec<(String, String)>, u64) -> BoxFuture<'static, Result<(u16, String), String>>
        + Send
        + Sync,
>;

/// Options of [`pwned_passwords`].
#[derive(Clone, Default)]
pub struct PwnedPasswordsOptions {
    /// Minimum breach count that rejects a password (default 1).
    pub threshold: Option<f64>,
    pub fail_closed: bool,
    pub timeout_ms: Option<u64>,
    pub endpoint: Option<String>,
    /// Replaces the HTTP client (`fetch`).
    pub fetch: Option<PwnedFetchFn>,
}

/// `pwnedPasswords(options)`: a Have I Been Pwned "range" client (k-anonymity) that hashes the password with SHA-1,
/// sends only the first five hex characters, and matches the returned suffixes locally. Network failures accept
/// the password unless `fail_closed`.
pub fn pwned_passwords(options: PwnedPasswordsOptions) -> BreachFn {
    let threshold = options.threshold.unwrap_or(1.0);
    let mut endpoint = options
        .endpoint
        .clone()
        .unwrap_or_else(|| "https://api.pwnedpasswords.com/range/".to_owned());
    if !endpoint.ends_with('/') {
        endpoint.push('/');
    }
    let timeout = options.timeout_ms.unwrap_or(3_000);
    let fail_closed = options.fail_closed;
    let fetch = options.fetch.clone().unwrap_or_else(default_fetch);
    Arc::new(move |password: String| {
        let endpoint = endpoint.clone();
        let fetch = fetch.clone();
        Box::pin(async move {
            let digest = crate::util::hex(Sha1::digest(password.as_bytes())).to_uppercase();
            let (prefix, suffix) = digest.split_at(5);
            let outcome = fetch(
                format!("{endpoint}{prefix}"),
                vec![("add-padding".to_owned(), "true".to_owned())],
                timeout,
            )
            .await;
            let found = match outcome {
                Ok((status, body)) if (200..300).contains(&status) => Ok(body
                    .split('\n')
                    .map(|line| line.strip_suffix('\r').unwrap_or(line))
                    .any(|line| {
                        let mut parts = js::trim(line).split(':');
                        let candidate = parts.next();
                        let count = parts.next();
                        candidate.is_some_and(|candidate| candidate.to_uppercase() == suffix)
                            && count.map(js::string_to_number).unwrap_or(f64::NAN) >= threshold
                    })),
                Ok((status, _)) => Err(format!("HTTP {status}")),
                Err(error) => Err(error),
            };
            match found {
                Ok(found) => Ok(found),
                Err(_) if fail_closed => Err(IamError::with_status(
                    "PASSWORD_CHECK_UNAVAILABLE",
                    "Password screening is unavailable",
                    503,
                )),
                Err(_) => Ok(false),
            }
        })
    })
}

fn default_fetch() -> PwnedFetchFn {
    Arc::new(|url, headers, timeout| {
        Box::pin(async move {
            let response = tokio::time::timeout(
                std::time::Duration::from_millis(timeout),
                crate::safe_fetch::plain_get(&url, &headers),
            )
            .await
            .map_err(|_| "TimeoutError".to_owned())?
            .map_err(|error| error.to_string())?;
            Ok(response)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screens_common_and_sequential_passwords() {
        assert!(is_common_password("Password1234"));
        assert!(is_common_password("aaaaaaaaaaaaaaa"));
        assert!(is_common_password("qwertyuiopasdf"));
        assert!(is_common_password("zyxwvutsrqponm"));
        assert!(!is_common_password("a strong root test password"));
        assert_eq!(character_classes("aB3!"), 4);
    }
}
