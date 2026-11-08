//! `better-iam api` (`commands/api.ts`): any API method as the current token.

use std::path::Path;
use std::sync::LazyLock;

use better_iam_core::js;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::errors::{CliError, CliResult, io_error, usage_error};
use crate::framework::{
    ApiOptions, ArgSpec, CliIo, CommandContext, CommandSpec, CommandTarget, FlagSpec,
    define_command,
};
use crate::output::{OutputFormat, format_result};
use crate::paths::resolve_path;
use crate::transport::{is_public_route, list_routes, parse_endpoint, route_path};

const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// Sets `a.b.c` (and `list[]` to append) on a plain object, refusing prototype keys.
fn assign(target: &mut Map<String, Value>, key: &str, value: Value) -> CliResult<()> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.iter().any(|part| {
        part.is_empty() || UNSAFE_KEYS.contains(&part.strip_suffix("[]").unwrap_or(part))
    }) {
        return Err(usage_error(
            format!("{key} is not a usable field name"),
            None,
        ));
    }
    let mut current = target;
    for (index, raw) in parts.iter().enumerate() {
        let append = raw.ends_with("[]");
        let part = if append { &raw[..raw.len() - 2] } else { raw };
        let last = index == parts.len() - 1;
        if last {
            if append {
                let mut items = match current.get(part) {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items.clone(),
                    Some(_) => {
                        return Err(usage_error(
                            format!("{part} is already set to a non-list value"),
                            None,
                        ));
                    }
                };
                items.push(value);
                current.insert(part.to_owned(), Value::Array(items));
            } else {
                current.insert(part.to_owned(), value);
            }
            return Ok(());
        }
        if append {
            return Err(usage_error(
                format!("{key}: [] may only end a field name"),
                None,
            ));
        }
        match current.get(part) {
            None => {
                current.insert(part.to_owned(), Value::Object(Map::new()));
            }
            Some(Value::Object(_)) => {}
            Some(_) => {
                return Err(usage_error(
                    format!("{part} is already set to a non-object value"),
                    None,
                ));
            }
        }
        let Some(Value::Object(next)) = current.get_mut(part) else {
            return Err(usage_error(
                format!("{part} is already set to a non-object value"),
                None,
            ));
        };
        current = next;
    }
    Ok(())
}

fn read_json(text: &str, source: &str) -> CliResult<Value> {
    js::parse(text).map_err(|_| usage_error(format!("{source} is not valid JSON"), None))
}

fn read_text(cwd: &Path, file: &str) -> CliResult<String> {
    let path = resolve_path(cwd, Path::new(file));
    std::fs::read_to_string(&path).map_err(|error| io_error(&error, "open", &path))
}

/// Drops prototype keys at every depth (the `JSON.parse` reviver).
fn without_unsafe_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(key, _)| !UNSAFE_KEYS.contains(&key.as_str()))
                .map(|(key, item)| (key, without_unsafe_keys(item)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(without_unsafe_keys).collect()),
        other => other,
    }
}

static ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)^([^=:]+)(:=|=)(.*)$").expect("regex"));

/// Builds the request body from `--data` (JSON, `@file.json`, or `-` for stdin) and `key=value` items, like HTTPie:
/// `name=Admin` (string), `limit:=10` / `actions:='["a"]'` (JSON), `document:=@policy.json` (JSON file),
/// `content=@terms.md` (file text), `resource.type=project` (nested), `actions[]=a` (append). A value that must start
/// with `@` without reading a file is escaped as `key=\@text` (`requestBody`).
pub async fn request_body(
    io: &CliIo,
    cwd: &Path,
    data: Option<&str>,
    items: &[String],
) -> CliResult<Map<String, Value>> {
    let mut body: Map<String, Value> = Map::new();
    if let Some(data) = data {
        let parsed = if data == "-" {
            let Some(stdin) = &io.stdin else {
                return Err(usage_error("--data - needs standard input", None));
            };
            read_json(&stdin().await?, "Standard input")?
        } else if let Some(file) = data.strip_prefix('@') {
            read_json(&read_text(cwd, file)?, file)?
        } else {
            read_json(data, "--data")?
        };
        match without_unsafe_keys(parsed) {
            Value::Object(map) => body = map,
            _ => return Err(usage_error("--data must be a JSON object", None)),
        }
    }
    for item in items {
        let Some(captures) = ITEM.captures(item) else {
            return Err(usage_error(
                format!("{item} is not key=value or key:=json"),
                Some("Quote values with spaces; see better-iam help api."),
            ));
        };
        let key = &captures[1];
        let operator = &captures[2];
        let raw = &captures[3];
        let value = if operator == ":=" {
            match raw.strip_prefix('@') {
                Some(file) => read_json(&read_text(cwd, file)?, file)?,
                None => read_json(raw, &format!("{key}:="))?,
            }
        } else if raw.starts_with("\\@") {
            // `key=\@text` sends the literal "@text" (as in httpie), for values that must never read a file.
            Value::String(raw[1..].to_owned())
        } else if raw.starts_with('@') && raw.len() > 1 {
            Value::String(read_text(cwd, &raw[1..])?)
        } else {
            Value::String(raw.to_owned())
        };
        assign(&mut body, js::trim(key), value)?;
    }
    Ok(body)
}

/// The base path `api --list` shows: the configuration's, else the --url's, else the default.
fn route_base_path(context: &CommandContext) -> CliResult<String> {
    let flags = &context.flags;
    let configured = context.config_path()?.is_some()
        || context
            .env
            .get("BETTER_IAM_DATABASE_URL")
            .is_some_and(|url| !url.is_empty());
    if flags.string("url").is_none() && configured {
        return Ok(context.iam()?.endpoint.base_path.clone());
    }
    // The route table is the same for every deployment of this version. Plugin endpoints are not listed; call them as
    // plugins/{pluginId}/{path}.
    Ok(match flags.string("url") {
        Some(url) => parse_endpoint(url)?.base_path,
        None => "/api/iam".to_owned(),
    })
}

static GROUP_OF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[./].*$").expect("regex"));

pub fn api_commands() -> Vec<CommandSpec> {
    vec![
        define_command("api", "Call any IAM API method as the current token", |context| async move {
            let flags = &context.flags;
            let route = context.args.first().cloned();
            let items: Vec<String> = context.args.iter().skip(1).cloned().collect();
            if flags.boolean("list") || route.is_none() {
                if !items.is_empty() {
                    return Err(usage_error("api --list takes at most a group name", None));
                }
                let base_path = route_base_path(&context)?;
                let group = route.as_deref().map(|route| GROUP_OF.replace(route, "").into_owned());
                let routes: Vec<Value> = list_routes()
                    .into_iter()
                    .filter(|entry| {
                        group
                            .as_deref()
                            .is_none_or(|group| group.is_empty() || entry.route.split('/').next() == Some(group))
                    })
                    .map(|entry| {
                        json!({
                            "method": entry.route.replacen('/', ".", 1),
                            "access": entry.access,
                            "http": format!("POST {base_path}/{}", entry.route),
                        })
                    })
                    .collect();
                if let Some(group) = group.as_deref().filter(|group| !group.is_empty())
                    && routes.is_empty()
                {
                    return Err(CliError::hinted(
                        "NOT_FOUND",
                        format!("No API group named {group}"),
                        "Run better-iam api --list for all groups.",
                    ));
                }
                // A table by default: this is for reading; --format json gives tools the same rows.
                (context.io.out)(&format_result(
                    &Value::Array(routes),
                    Some(flags.format().unwrap_or(OutputFormat::Table)),
                    flags.query(),
                )?);
                return Ok(None);
            }
            let route = route.unwrap_or_default();
            let path = route_path(&route)?;
            let mut body = request_body(&context.io, &context.cwd, flags.string("data"), &items).await?;
            if let Some(tenant) = flags.string("tenant")
                && !body.contains_key("tenantId")
            {
                body.insert("tenantId".into(), Value::String(tenant.to_owned()));
            }
            // MFA enrollment is public for a sign-in challenge but uses the caller's own session without one.
            let nested_challenge = match body.get("credential") {
                Some(Value::Object(nested)) => matches!(nested.get("challenge"), Some(Value::String(_))),
                _ => false,
            };
            let own_session = (path == "auth/beginMfa" && !matches!(body.get("challenge"), Some(Value::String(_))))
                || (path == "auth/confirmMfa" && !nested_challenge);
            let transport = context.api(ApiOptions {
                anonymous: !(own_session || !is_public_route(&path)),
                token: None,
            })?;
            Ok(Some(transport.call(&path, Some(body)).await?))
        })
        .group("API")
        .description(
            "api calls any method of the HTTP API (the same routes and permission checks as POST {basePath}/{group}/{method}) as BETTER_IAM_TOKEN or the session saved by login, in process through the configuration or against --url, and prints the result. Build the input with --data (JSON, @file.json, or - for standard input) and key=value items: name=Admin sets a string, limit:=10 or actions:='[\"a\",\"b\"]' sets JSON, document:=@policy.json reads a JSON file, content=@terms.md reads a text file, resource.type=project nests, and actions[]=a appends. --tenant (or BETTER_IAM_TENANT, or the saved profile) fills tenantId when the input has none. api --list [GROUP] lists every route with whether it needs a credential.",
        )
        .usage(
            "better-iam api GROUP.METHOD [key=value ...] [--data JSON|@FILE|-] [--tenant TENANT_ID] [--list] [--url URL] [--profile NAME]",
        )
        .target(CommandTarget::Token)
        .arg(ArgSpec::new("route", "group.method (roles.create, auth.getSession) or authorize"))
        .arg(
            ArgSpec::new(
                "fields",
                "key=value, key:=json, key:=@file.json, key=@file.txt (key=\\@text sends a literal @text)",
            )
            .variadic(),
        )
        .flag(
            "data",
            FlagSpec::string("Request body as JSON, a JSON file, or standard input").value("JSON|@FILE|-"),
        )
        .flag(
            "tenant",
            FlagSpec::string("tenantId for inputs that do not set one")
                .value("TENANT_ID")
                .env("BETTER_IAM_TENANT")
                .profile("tenantId"),
        )
        .flag(
            "list",
            FlagSpec::boolean("List routes (optionally of one group) instead of calling one"),
        )
        .examples(&[
            "better-iam api --list roles",
            "better-iam api roles.create name=Reader permissions:='[\"documents:read\"]'",
            "better-iam api policies.create name=Deny-deletes document:=@deny.json --tenant ten_123",
            "better-iam api identities.list limit:=5 --query \"[].email\"",
            "echo '{\"slug\":\"acme\"}' | better-iam api tenants.lookup --data -",
        ]),
    ]
}
