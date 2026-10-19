//! The options as a model value: what the TypeScript validators see when they read `options` (`resolveConfig`, the
//! catalog, and the module settings resolvers). Members are spelled as in TypeScript; callbacks appear as
//! [`crate::js::function_marker`]s; absent options are absent (Rust-only module).
//!
//! Options read from a standalone JSON file ([`crate::standalone_config`]) carry the JSON they were read from, with
//! the callbacks the reader supplied (deliveries, scripted callbacks) as function markers, so validation sees exactly
//! what the TypeScript reader hands `betterIam()`.

use std::sync::Arc;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::js::function_marker;
use crate::options::{BetterIamOptions, ServerAuthOptions};

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn object_of<T: Serialize>(value: &T) -> Map<String, Value> {
    match to_value(value) {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn mark(map: &mut Map<String, Value>, key: &str, present: bool) {
    if present {
        map.insert(key.to_owned(), function_marker());
    }
}

fn set_number(map: &mut Map<String, Value>, key: &str, value: Option<f64>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), crate::js::number(value));
    }
}

fn set_bool(map: &mut Map<String, Value>, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), Value::Bool(value));
    }
}

/// The `authentication` member as a model value.
pub fn auth_options_value(options: &ServerAuthOptions) -> Value {
    let mut map = Map::new();
    if let Some(name) = &options.app_name {
        map.insert("appName".into(), Value::String(name.clone()));
    }
    set_bool(&mut map, "signUpEnabled", options.sign_up_enabled);
    set_bool(
        &mut map,
        "requireEmailVerification",
        options.require_email_verification,
    );
    set_bool(&mut map, "emailPassword", options.email_password);
    set_bool(&mut map, "passwordlessEmail", options.passwordless_email);
    set_bool(&mut map, "passwordlessSms", options.passwordless_sms);
    mark(&mut map, "sendEmail", options.send_email.is_some());
    mark(&mut map, "sendSms", options.send_sms.is_some());
    mark(
        &mut map,
        "deliverWebhook",
        options.deliver_webhook.is_some(),
    );
    set_number(
        &mut map,
        "maxDeliveryAttempts",
        options.max_delivery_attempts,
    );
    set_number(&mut map, "sessionLifetimeMs", options.session_lifetime_ms);
    set_number(
        &mut map,
        "sessionIdleTimeoutMs",
        options.session_idle_timeout_ms,
    );
    set_number(
        &mut map,
        "recentAuthenticationMs",
        options.recent_authentication_ms,
    );
    set_number(
        &mut map,
        "trustedDeviceLifetimeMs",
        options.trusted_device_lifetime_ms,
    );
    set_bool(
        &mut map,
        "signInNotifications",
        options.sign_in_notifications,
    );
    set_bool(&mut map, "mfaEmailCodes", options.mfa_email_codes);
    set_number(
        &mut map,
        "failedSignInAlerts",
        options.failed_sign_in_alerts,
    );
    if let Some(limits) = &options.rate_limits {
        let mut rate = Map::new();
        set_number(&mut rate, "attempts", limits.attempts);
        set_number(&mut rate, "sensitiveAttempts", limits.sensitive_attempts);
        set_number(&mut rate, "windowMs", limits.window_ms);
        set_number(&mut rate, "ipAttempts", limits.ip_attempts);
        mark(&mut rate, "limiter", limits.limiter.is_some());
        map.insert("rateLimits".into(), Value::Object(rate));
    }
    mark(&mut map, "requireMfa", options.require_mfa.is_some());
    if let Some(passkeys) = &options.passkeys {
        let mut keys = Map::new();
        keys.insert("rpID".into(), Value::String(passkeys.rp_id.clone()));
        if let Some(name) = &passkeys.rp_name {
            keys.insert("rpName".into(), Value::String(name.clone()));
        }
        map.insert("passkeys".into(), Value::Object(keys));
    }
    mark(&mut map, "onAudit", options.on_audit.is_some());
    mark(&mut map, "now", options.now.is_some());
    if let Some(policy) = &options.password_policy {
        let mut screening = Map::new();
        set_bool(
            &mut screening,
            "blockCommonPasswords",
            policy.block_common_passwords,
        );
        mark(&mut screening, "isBreached", policy.is_breached.is_some());
        mark(&mut screening, "check", policy.check.is_some());
        map.insert("passwordPolicy".into(), Value::Object(screening));
    }
    Value::Object(map)
}

/// `options` as the TypeScript validators read it.
pub fn options_value(options: &BetterIamOptions) -> Arc<Value> {
    if let Some(model) = &options.model {
        return model.clone();
    }
    let mut map = Map::new();
    if options.database.is_some() {
        map.insert("database".into(), Value::Object(Map::new()));
    }
    map.insert("secret".into(), Value::String(options.secret.clone()));
    if let Some(previous) = &options.previous_secrets {
        map.insert("previousSecrets".into(), to_value(previous));
    }
    map.insert("baseURL".into(), Value::String(options.base_url.clone()));
    if let Some(path) = &options.base_path {
        map.insert("basePath".into(), Value::String(path.clone()));
    }
    if let Some(origins) = &options.trusted_origins {
        map.insert("trustedOrigins".into(), to_value(origins));
    }
    if let Some(authentication) = &options.authentication {
        map.insert("authentication".into(), auth_options_value(authentication));
    }
    if let Some(hierarchy) = &options.hierarchy {
        map.insert("hierarchy".into(), to_value(hierarchy));
    }
    if let Some(permissions) = &options.permissions {
        map.insert("permissions".into(), to_value(permissions));
    }
    if let Some(onboarding) = &options.onboarding {
        map.insert("onboarding".into(), to_value(onboarding));
    }
    if let Some(plugins) = &options.plugins {
        let list = plugins
            .iter()
            .map(|plugin| {
                let mut entry = Map::new();
                entry.insert("id".into(), Value::String(plugin.id().to_owned()));
                Value::Object(entry)
            })
            .collect();
        map.insert("plugins".into(), Value::Array(list));
    }
    if let Some(events) = &options.events {
        let mut entry = object_of(events);
        mark(&mut entry, "onEvent", events.on_event.is_some());
        mark(
            &mut entry,
            "deliverWebhook",
            events.deliver_webhook.is_some(),
        );
        map.insert("events".into(), Value::Object(entry));
    }
    if let Some(archive) = &options.audit_archive {
        let mut entry = object_of(archive);
        mark(&mut entry, "write", archive.write.is_some());
        map.insert("auditArchive".into(), Value::Object(entry));
    }
    if let Some(requests) = &options.access_requests {
        map.insert("accessRequests".into(), to_value(requests));
    }
    if let Some(observability) = &options.observability {
        let mut entry = Map::new();
        mark(&mut entry, "onSpan", observability.on_span.is_some());
        if let Some(metrics) = &observability.metrics {
            entry.insert("metrics".into(), to_value(metrics));
        }
        map.insert("observability".into(), Value::Object(entry));
    }
    if let Some(usage) = &options.access_usage {
        map.insert("accessUsage".into(), to_value(usage));
    }
    if let Some(inference) = &options.inference {
        map.insert("inference".into(), to_value(inference));
    }
    if let Some(a2a) = &options.a2a {
        map.insert("a2a".into(), to_value(a2a));
    }
    if let Some(billing) = &options.billing {
        map.insert("billing".into(), to_value(billing));
    }
    if let Some(ssh) = &options.ssh {
        map.insert("ssh".into(), to_value(ssh));
    }
    if let Some(credentials) = &options.verifiable_credentials {
        map.insert("verifiableCredentials".into(), to_value(credentials));
    }
    if let Some(clearances) = &options.clearances {
        map.insert("clearances".into(), to_value(clearances));
    }
    if let Some(vault) = &options.vault {
        let mut entry = object_of(vault);
        if let Some(rotators) = &vault.rotators {
            let mut list = Map::new();
            for name in rotators.keys() {
                let mut rotator = Map::new();
                mark(&mut rotator, "rotate", true);
                list.insert(name.clone(), Value::Object(rotator));
            }
            entry.insert("rotators".into(), Value::Object(list));
        }
        if let Some(engines) = &vault.engines {
            let mut list = Map::new();
            for (name, engine) in engines {
                let mut methods = Map::new();
                mark(&mut methods, "issue", true);
                mark(&mut methods, "revoke", engine.has_revoke());
                mark(&mut methods, "renew", engine.has_renew());
                list.insert(name.clone(), Value::Object(methods));
            }
            entry.insert("engines".into(), Value::Object(list));
        }
        map.insert("vault".into(), Value::Object(entry));
    }
    if let Some(http) = &options.http {
        let mut entry = object_of(http);
        mark(&mut entry, "clientInfo", http.client_info.is_some());
        map.insert("http".into(), Value::Object(entry));
    }
    if let Some(defaults) = &options.tenant_defaults {
        map.insert("tenantDefaults".into(), to_value(defaults));
    }
    if let Some(domains) = &options.domains {
        let mut entry = object_of(domains);
        mark(&mut entry, "resolveTxt", domains.resolve_txt.is_some());
        map.insert("domains".into(), Value::Object(entry));
    }
    if let Some(hosts) = &options.hosts {
        map.insert("hosts".into(), to_value(hosts));
    }
    if let Some(regions) = &options.regions {
        let mut entry = object_of(regions);
        mark(&mut entry, "locate", regions.locate.is_some());
        map.insert("regions".into(), Value::Object(entry));
    }
    mark(
        &mut map,
        "resolveResource",
        options.resolve_resource.is_some(),
    );
    mark(
        &mut map,
        "resolveContext",
        options.resolve_context.is_some(),
    );
    if let Some(protocols) = &options.protocols {
        let list = protocols
            .iter()
            .map(|_| {
                let mut entry = Map::new();
                mark(&mut entry, "handle", true);
                Value::Object(entry)
            })
            .collect();
        map.insert("protocols".into(), Value::Array(list));
    }
    if let Some(sts) = &options.sts {
        let mut entry = object_of(sts);
        if let Some(web) = &sts.web_identity
            && web.fetch_json.is_some()
            && let Some(Value::Object(web_entry)) = entry.get_mut("webIdentity")
        {
            mark(web_entry, "fetchJson", true);
        }
        map.insert("sts".into(), Value::Object(entry));
    }
    if let Some(signals) = &options.signals {
        map.insert("signals".into(), to_value(signals));
    }
    Arc::new(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::is_function;
    use crate::options::{StsOptions, StsWebIdentityOptions};

    #[test]
    fn callbacks_become_markers() {
        let options = BetterIamOptions {
            base_url: "https://iam.example.com".into(),
            sts: Some(StsOptions {
                web_identity: Some(StsWebIdentityOptions {
                    enabled: Some(true),
                    fetch_json: Some(Arc::new(|_| Box::pin(async { Ok(Value::Null) }))),
                    ..StsWebIdentityOptions::default()
                }),
                ..StsOptions::default()
            }),
            resolve_resource: Some(Arc::new(|reference| {
                Box::pin(async move { Ok(crate::options::ResolvedResource::of(&reference)) })
            })),
            ..BetterIamOptions::default()
        };
        let value = options_value(&options);
        assert!(is_function(value.pointer("/sts/webIdentity/fetchJson")));
        assert_eq!(
            value.pointer("/sts/webIdentity/enabled"),
            Some(&Value::Bool(true))
        );
        assert!(is_function(value.get("resolveResource")));
        assert!(value.get("database").is_none());
    }
}
