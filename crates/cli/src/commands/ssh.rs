//! SSH certificates (`commands/ssh.ts`): people get one for what policies allow; hosts enroll and check in; the sweep
//! job.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use better_iam_core::js;
use serde_json::{Value, json};

use super::{members, object, only_tenant, tenant_flag, to_json};
use crate::errors::{CliError, CliResult, io_error, usage_error};
use crate::framework::{
    ApiOptions, CommandContext, CommandSpec, CommandTarget, FlagSpec, define_command,
};
use crate::paths::{display, home_dir};

fn comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

const RENEWAL_TOKEN_PATH: &str = "/etc/ssh/better-iam/renewal-token";

/// `path.posix.normalize(path)`.
fn posix_normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = parts.join("/");
    if absolute {
        out = format!("/{out}");
    }
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    if out.is_empty() { ".".to_owned() } else { out }
}

/// Only files under /etc/ssh, never outside it: the host trusts the server, but not blindly with paths.
fn host_file_path(root: &Path, path: &str) -> CliResult<PathBuf> {
    let normal = posix_normalize(path);
    if !normal.starts_with("/etc/ssh/") || normal.contains("..") || normal != path {
        let prefix = String::from_utf16_lossy(&path.encode_utf16().take(80).collect::<Vec<u16>>());
        return Err(CliError::new(
            "UNEXPECTED_RESPONSE",
            format!("The server named a file outside /etc/ssh: {prefix}"),
            None,
        ));
    }
    let mut target = root.to_path_buf();
    for segment in normal.split('/').filter(|segment| !segment.is_empty()) {
        target.push(segment);
    }
    Ok(target)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// `writeFile(path, content, { mode })`: replaces the file; the mode applies to a new file and is tightened on an
/// existing one (a no-op on Windows).
fn write_file(path: &Path, content: &[u8], mode: u32) -> CliResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    use std::io::Write as _;
    let mut file = options
        .open(path)
        .map_err(|error| io_error(&error, "open", path))?;
    file.write_all(content)
        .map_err(|error| io_error(&error, "write", path))?;
    let _ = mode;
    Ok(())
}

fn mkdir_all(path: &Path) -> CliResult<()> {
    std::fs::create_dir_all(path).map_err(|error| io_error(&error, "mkdir", path))
}

/// A file `ssh/enrollHost` and `ssh/syncHost` return.
struct HostFile {
    path: String,
    content: String,
    mode: String,
    base64: bool,
}

fn host_files(setup: &Value) -> Vec<HostFile> {
    let mut files: Vec<HostFile> = setup
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|file| HostFile {
            path: better_iam_server::js::js_string(file.get("path")),
            content: better_iam_server::js::js_string(file.get("content")),
            mode: better_iam_server::js::js_string(file.get("mode")),
            base64: file.get("encoding").and_then(Value::as_str) == Some("base64"),
        })
        .collect();
    if let Some(token) = setup
        .get("renewalToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
    {
        files.push(HostFile {
            path: RENEWAL_TOKEN_PATH.into(),
            content: format!("{token}\n"),
            mode: "0600".into(),
            base64: false,
        });
    }
    files
}

/// `Number.parseInt(mode, 8)`.
fn octal(mode: &str) -> u32 {
    let digits: String = mode
        .trim_start()
        .chars()
        .take_while(|c| ('0'..='7').contains(c))
        .collect();
    u32::from_str_radix(&digits, 8).unwrap_or(0)
}

fn write_host_files(
    context: &CommandContext,
    root: &Path,
    setup: &Value,
    dry_run: bool,
) -> CliResult<Vec<String>> {
    let mut written: Vec<String> = Vec::new();
    let files = host_files(setup);
    for file in &files {
        let target = host_file_path(root, &file.path)?;
        written.push(file.path.clone());
        if dry_run {
            continue;
        }
        if let Some(parent) = target.parent() {
            mkdir_all(parent)?;
        }
        let content = if file.base64 {
            base64::engine::general_purpose::STANDARD
                .decode(file.content.as_bytes())
                .unwrap_or_default()
        } else {
            file.content.clone().into_bytes()
        };
        write_file(&target, &content, octal(&file.mode))?;
        // Also tighten an existing file (the mode applies to new files only); a no-op on Windows.
        set_mode(&target, octal(&file.mode));
    }
    // A login removed from the host must stop working here too: its principals file goes.
    let managed: Vec<String> = setup
        .get("managedDirectories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|directory| better_iam_server::js::js_string(Some(directory)))
        .collect();
    for directory in managed {
        let folder = host_file_path(
            root,
            &format!("{}/", directory.strip_suffix('/').unwrap_or(&directory)),
        )?;
        let listed: HashSet<PathBuf> = files
            .iter()
            .filter_map(|file| host_file_path(root, &file.path).ok())
            .collect();
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let mut present: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        present.sort();
        for name in present {
            let target = folder.join(&name);
            if listed.contains(&target) {
                continue;
            }
            written.push(format!(
                "-{}",
                posix_normalize(&format!("{directory}/{name}"))
            ));
            if !dry_run {
                let _ = std::fs::remove_file(&target);
            }
        }
    }
    if !dry_run {
        context.note("Wrote the SSH files; reload sshd to apply them (systemctl reload ssh).");
    }
    Ok(written)
}

fn root_flag() -> FlagSpec {
    FlagSpec::string("Write under this directory instead of / (for images and tests)")
        .value("DIR")
        .default_text("/")
}

fn iso(value: Option<&Value>) -> Value {
    value
        .and_then(js::as_number)
        .and_then(js::iso_string)
        .map_or(Value::Null, Value::String)
}

pub fn ssh_commands() -> Vec<CommandSpec> {
    vec![
        define_command("ssh-cert", "Get a short-lived SSH certificate for your key", |context| async move {
            let flags = &context.flags;
            let default_key = home_dir().unwrap_or_default().join(".ssh").join("id_ed25519.pub");
            let key_path = context.path(&flags.string("key").map_or_else(|| display(&default_key), str::to_owned));
            if !display(&key_path).ends_with(".pub") {
                return Err(usage_error("--key must name the .pub public key file", None));
            }
            let public_key = std::fs::read_to_string(&key_path)
                .map_err(|_| {
                    CliError::hinted(
                        "NOT_FOUND",
                        format!("No public key at {}", display(&key_path)),
                        "Create one with ssh-keygen -t ed25519.",
                    )
                })?
                .trim()
                .to_owned();
            let issued = context
                .api(ApiOptions::default())?
                .call(
                    "ssh/issueCertificate",
                    members(object(vec![
                        ("tenantId", flags.string("tenant").map(Value::from)),
                        ("publicKey", Some(Value::from(public_key))),
                        ("hosts", flags.string("hosts").map(|hosts| json!(comma_list(hosts)))),
                        ("logins", flags.string("logins").map(|logins| json!(comma_list(logins)))),
                        ("ttlMs", flags.integer("ttl-minutes").map(|minutes| Value::from(minutes * 60_000))),
                        ("reason", flags.string("reason").map(Value::from)),
                    ])),
                )
                .await?;
            let member = |key: &str| issued.get(key).cloned().unwrap_or(Value::Null);
            let mut summary = serde_json::Map::new();
            summary.insert("id".into(), member("id"));
            summary.insert("principals".into(), member("principals"));
            summary.insert("validBefore".into(), iso(issued.get("validBefore")));
            summary.insert("hosts".into(), member("hosts"));
            if flags.boolean("no-write") {
                summary.insert("certificate".into(), member("certificate"));
                summary.insert("knownHosts".into(), member("knownHosts"));
                return Ok(Some(Value::Object(summary)));
            }
            let key_text = display(&key_path);
            let certificate_path = PathBuf::from(format!("{}-cert.pub", &key_text[..key_text.len() - ".pub".len()]));
            let default_known = home_dir().unwrap_or_default().join(".ssh").join("better-iam_known_hosts");
            let known_hosts_path =
                context.path(&flags.string("known-hosts").map_or_else(|| display(&default_known), str::to_owned));
            write_file(
                &certificate_path,
                format!("{}\n", better_iam_server::js::js_string(issued.get("certificate"))).as_bytes(),
                0o644,
            )?;
            if let Some(parent) = known_hosts_path.parent() {
                mkdir_all(parent)?;
            }
            write_file(
                &known_hosts_path,
                better_iam_server::js::js_string(issued.get("knownHosts")).as_bytes(),
                0o644,
            )?;
            // Revoked host keys and certificates, for `RevokedHostKeys` in ~/.ssh/config.
            let known_text = display(&known_hosts_path);
            let revoked_hosts_path = PathBuf::from(format!(
                "{}_revoked_hosts",
                known_text.strip_suffix("_known_hosts").unwrap_or(&known_text)
            ));
            let revoked = base64::engine::general_purpose::STANDARD
                .decode(better_iam_server::js::js_string(issued.get("revokedHostKeys")).as_bytes())
                .unwrap_or_default();
            write_file(&revoked_hosts_path, &revoked, 0o644)?;
            summary.insert("certificatePath".into(), Value::String(display(&certificate_path)));
            summary.insert("knownHostsPath".into(), Value::String(known_text));
            summary.insert("revokedHostsPath".into(), Value::String(display(&revoked_hosts_path)));
            Ok(Some(Value::Object(summary)))
        })
        .group("Access")
        .description(
            "ssh-cert sends your public key (--key, default ~/.ssh/id_ed25519.pub) to the organization's SSH certificate authority as BETTER_IAM_TOKEN or the session saved by login, and saves the certificate it returns next to the key (id_ed25519-cert.pub), where ssh picks it up. The certificate names every enrolled host and login policies allow you (ssh:login on ssh-login/{host}/{login}), or only --hosts and --logins. It also writes the organization's host authority to --known-hosts (default ~/.ssh/better-iam_known_hosts): add that file to UserKnownHostsFile in ~/.ssh/config so hosts are verified by certificate, and the host revocation list written beside it (better-iam_revoked_hosts) to RevokedHostKeys.",
        )
        .target(CommandTarget::Token)
        .flag("tenant", tenant_flag())
        .flag(
            "key",
            FlagSpec::string("Your OpenSSH public key (default ~/.ssh/id_ed25519.pub)").value("PATH"),
        )
        .flag("hosts", FlagSpec::string("Only these hosts").value("HOST,..."))
        .flag("logins", FlagSpec::string("Only these logins").value("LOGIN,..."))
        .flag(
            "ttl-minutes",
            FlagSpec::integer("Lifetime (default and maximum from the organization's settings)")
                .min(1)
                .max(10080),
        )
        .flag("reason", FlagSpec::string("Why you need access (audited)").value("TEXT"))
        .flag(
            "known-hosts",
            FlagSpec::string("Where to write the known_hosts lines (default ~/.ssh/better-iam_known_hosts)")
                .value("PATH"),
        )
        .flag("no-write", FlagSpec::boolean("Print the certificate instead of saving files"))
        .examples(&[
            "better-iam ssh-cert --tenant ten_123",
            "better-iam ssh-cert --hosts web-01 --logins deploy --ttl-minutes 30 --reason \"hotfix 42\"",
        ]),
        define_command("ssh-host-enroll", "Enroll this server with the SSH certificate authority", |context| async move {
            let flags = &context.flags;
            let key_path = context.path(flags.string("host-key").unwrap_or("/etc/ssh/ssh_host_ed25519_key.pub"));
            let host_key = std::fs::read_to_string(&key_path)
                .map_err(|error| io_error(&error, "open", &key_path))?
                .trim()
                .to_owned();
            let setup = context
                .api(ApiOptions {
                    anonymous: true,
                    token: None,
                })?
                .call(
                    "ssh/enrollHost",
                    members(json!({
                        "joinToken": flags.string("join-token").unwrap_or_default(),
                        "publicKey": host_key,
                    })),
                )
                .await?;
            let root = context.path(flags.string("root").unwrap_or("/"));
            let files = write_host_files(&context, &root, &setup, flags.boolean("dry-run"))?;
            let host = setup.get("host");
            Ok(Some(json!({
                "host": host.and_then(|host| host.get("name")).cloned().unwrap_or(Value::Null),
                "hostId": host.and_then(|host| host.get("id")).cloned().unwrap_or(Value::Null),
                "certificateExpiresAt": iso(setup.get("certificateExpiresAt")),
                "files": files,
                "next": "Schedule better-iam ssh-host-sync every 5 minutes, then reload sshd.",
            })))
        })
        .group("Setup")
        .description(
            "ssh-host-enroll runs on a server: it sends the server's public host key (--host-key, default /etc/ssh/ssh_host_ed25519_key.pub) with the one-time join token from ssh.createHost, and writes what sshd needs under /etc/ssh: the host certificate, the trusted user authority, one principals file per login, the key revocation list, an sshd_config.d drop-in, and the renewal token (root-only) that ssh-host-sync uses from then on. Needs no session; point it at the server with --url.",
        )
        .target(CommandTarget::Token)
        .flag(
            "join-token",
            FlagSpec::string("The one-time join token from ssh.createHost or ssh.resetJoinToken")
                .value("TOKEN")
                .required()
                .env("BETTER_IAM_SSH_JOIN_TOKEN"),
        )
        .flag(
            "host-key",
            FlagSpec::string("The server's public host key")
                .value("PATH")
                .default_text("/etc/ssh/ssh_host_ed25519_key.pub"),
        )
        .flag("root", root_flag())
        .flag("dry-run", FlagSpec::boolean("List the files without writing them"))
        .examples(&["BETTER_IAM_SSH_JOIN_TOKEN=biam_sshj.... better-iam ssh-host-enroll --url https://iam.example.com"]),
        define_command(
            "ssh-host-sync",
            "Refresh this server's SSH trust, principals, revocations and certificate",
            |context| async move {
                let flags = &context.flags;
                let root = context.path(flags.string("root").unwrap_or("/"));
                let token_file = match flags.string("renewal-token-file") {
                    Some(file) => context.path(file),
                    None => host_file_path(&root, RENEWAL_TOKEN_PATH)?,
                };
                let renewal_token = std::fs::read_to_string(&token_file)
                    .map_err(|_| {
                        CliError::hinted(
                            "NOT_FOUND",
                            format!("No renewal token at {}", display(&token_file)),
                            "Enroll the host with ssh-host-enroll first.",
                        )
                    })?
                    .trim()
                    .to_owned();
                let setup = context
                    .api(ApiOptions {
                        anonymous: true,
                        token: None,
                    })?
                    .call(
                        "ssh/syncHost",
                        members(object(vec![
                            ("renewalToken", Some(Value::from(renewal_token))),
                            ("renew", flags.boolean("renew").then_some(Value::Bool(true))),
                        ])),
                    )
                    .await?;
                let files = write_host_files(&context, &root, &setup, flags.boolean("dry-run"))?;
                Ok(Some(json!({
                    "host": setup.get("host").and_then(|host| host.get("name")).cloned().unwrap_or(Value::Null),
                    "certificateRenewed": setup.get("certificateRenewed").cloned().unwrap_or(Value::Null),
                    "certificateExpiresAt": iso(setup.get("certificateExpiresAt")),
                    "revocationVersion": setup.get("revocationVersion").cloned().unwrap_or(Value::Null),
                    "files": files,
                })))
            },
        )
        .group("Operations")
        .description(
            "ssh-host-sync runs on an enrolled server (every few minutes, from cron or a systemd timer): with the renewal token ssh-host-enroll saved, it fetches the current trusted user authorities, principals files and key revocation list, and a new host certificate when the current one nears its end or the host's addresses changed, and rewrites the files. Reload sshd when the certificate or trust changed; revocations and principals apply to the next login without a reload.",
        )
        .target(CommandTarget::Token)
        .flag(
            "renewal-token-file",
            FlagSpec::string("Where ssh-host-enroll saved the renewal token")
                .value("PATH")
                .default_text(RENEWAL_TOKEN_PATH),
        )
        .flag("renew", FlagSpec::boolean("Issue a new host certificate now"))
        .flag("root", root_flag())
        .flag("dry-run", FlagSpec::boolean("List the files without writing them")),
        define_command("ssh-sweep", "Revoke SSH certificates whose holder or access went away", |context| async move {
            let input = super::tenant_input(&context.flags);
            let result = context.iam()?.ssh.sweep(Some(&input)).await?;
            Ok(Some(to_json(&result)?))
        })
        .group("Operations")
        .description(
            "ssh-sweep re-checks every live SSH user certificate (or one --tenant's): certificates of people and machines who are no longer active, whose temporary session ended, or whose hosts and logins policies no longer allow are revoked and published in the revocation list hosts fetch with ssh-host-sync. A deployment operation; run it every few minutes.",
        )
        .target(CommandTarget::Config)
        .flag("tenant", only_tenant()),
    ]
}
