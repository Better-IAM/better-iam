//! The SSH certificate authority modules (ssh-ca.ts, ssh.ts): ported from tests/ssh-ca.test.ts in full, and from the
//! module behaviors tests/ssh.test.ts exercises (authorities, trust bundles, revocation lists, the continuous
//! authorization sweep, host name and pattern rules, settings). tests/ssh.test.ts drives them through the `ssh` API
//! group (api/ssh.ts), a separate unit; here the records that API writes are written to the store the same way, and
//! the module functions are called directly.

mod organization_fixture;

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, IamStore, IamStoreExt, Tenant,
};
use better_iam_server::options::{SshOptions, Toggle};
use better_iam_server::ssh::*;
use better_iam_server::ssh_ca::*;
use indexmap::IndexMap;
use organization_fixture::{Org, code, organization, run};
use serde_json::{Value, json};

const HOUR: f64 = 3_600_000.0;

// --- tests/support/ssh.ts ------------------------------------------------------------------------------------------

fn write_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn mpint(value: &[u8]) -> Vec<u8> {
    if value[0] & 0x80 != 0 {
        let mut padded = vec![0];
        padded.extend_from_slice(value);
        padded
    } else {
        value.to_vec()
    }
}

/// A fresh OpenSSH public key line generated in-process (no ssh-keygen needed).
fn ssh_public_key(kind: &str, comment: &str) -> String {
    match kind {
        "ed25519" | "sk-ed25519" => {
            let key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let raw = key.verifying_key().to_bytes();
            let name = if kind == "ed25519" {
                "ssh-ed25519"
            } else {
                "sk-ssh-ed25519@openssh.com"
            };
            let blob = if kind == "sk-ed25519" {
                write_parts(&[name.as_bytes(), &raw, b"ssh:"])
            } else {
                write_parts(&[name.as_bytes(), &raw])
            };
            format!("{name} {} {comment}", STANDARD.encode(blob))
        }
        "ecdsa" => {
            let key = loop {
                if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
                    break key;
                }
            };
            let point = key.verifying_key().to_encoded_point(false);
            let blob = write_parts(&[b"ecdsa-sha2-nistp256", b"nistp256", point.as_bytes()]);
            format!("ecdsa-sha2-nistp256 {} {comment}", STANDARD.encode(blob))
        }
        _ => {
            use rsa::traits::PublicKeyParts;
            let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("rsa");
            let e = mpint(&key.e().to_bytes_be());
            let n = mpint(&key.n().to_bytes_be());
            let blob = write_parts(&[b"ssh-rsa", &e, &n]);
            format!("ssh-rsa {} {comment}", STANDARD.encode(blob))
        }
    }
}

fn key_value(line: &str) -> Value {
    Value::String(line.to_owned())
}

/// The system's ssh-keygen, when installed (OpenSSH on Linux/macOS, Windows' optional OpenSSH client).
fn ssh_keygen() -> Option<PathBuf> {
    for candidate in [
        "ssh-keygen",
        "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe",
    ] {
        match std::process::Command::new(candidate).arg("-?").output() {
            Ok(_) => return Some(PathBuf::from(candidate)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Some(PathBuf::from(candidate)),
        }
    }
    None
}

/// Runs ssh-keygen; returns the exit status and stdout with stderr folded in.
fn run_keygen(binary: &PathBuf, args: &[&std::ffi::OsStr]) -> (i32, String) {
    let output = std::process::Command::new(binary)
        .args(args)
        .output()
        .expect("ssh-keygen");
    (
        output.status.code().unwrap_or(1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn authority() -> SshSigningKey {
    let generated = generate_ssh_authority_key();
    ssh_signing_key(&generated.public_blob, &generated.private_pkcs8).expect("authority key")
}

fn message(error: &better_iam_core::IamError) -> &str {
    &error.message
}

// --- tests/ssh-ca.test.ts ------------------------------------------------------------------------------------------

#[test]
fn parses_every_supported_key_type_and_refuses_malformed_keys() {
    let fingerprint = regex::Regex::new(r"^SHA256:[A-Za-z0-9+/]{43}$").unwrap();
    for kind in ["ed25519", "ecdsa", "rsa", "sk-ed25519"] {
        let key = parse_ssh_public_key(
            Some(&key_value(&ssh_public_key(kind, "alice@laptop"))),
            None,
        )
        .expect(kind);
        assert!(
            fingerprint.is_match(&key.fingerprint),
            "{}",
            key.fingerprint
        );
        assert_eq!(key.comment.as_deref(), Some("alice@laptop"));
        assert_eq!(key.security_key, kind == "sk-ed25519");
        if kind == "rsa" {
            assert_eq!(key.bits, Some(2048.0));
        }
    }
    let good = ssh_public_key("ed25519", "test@example");
    let data = good.split(' ').nth(1).unwrap();
    let fails = |line: &str| parse_ssh_public_key(Some(&key_value(line)), None).unwrap_err();
    assert!(message(&fails("ssh-dss AAAA")).contains("Unsupported key type"));
    assert!(message(&fails(&format!("ecdsa-sha2-nistp256 {data}"))).contains("does not match"));
    fails(&format!("ssh-ed25519 {data}AAAA"));
    assert!(message(&fails("ssh-ed25519-cert-v01@openssh.com AAAA")).contains("not a certificate"));
    fails("ssh-ed25519");
    assert_eq!(code(&fails("ssh-ed25519")), "INVALID_INPUT");
    // Not a string at all.
    assert_eq!(
        code(&parse_ssh_public_key(Some(&json!(42)), None).unwrap_err()),
        "INVALID_INPUT"
    );
}

#[test]
fn issues_certificates_that_verify_decode_and_survive_a_round_trip() {
    let ca = authority();
    let key = parse_ssh_public_key(Some(&key_value(&ssh_public_key("ecdsa", "x"))), None).unwrap();
    let serial = ssh_serial();
    let mut critical_options = IndexMap::new();
    critical_options.insert("source-address".to_owned(), "203.0.113.7/32".to_owned());
    let signed = sign_ssh_certificate(
        &ca,
        &SshCertificateSpec {
            key: key.clone(),
            serial,
            kind: SSH_CERT_USER as u32,
            key_id: "alice@acme.test".into(),
            principals: vec!["deploy@web-01".into(), "root@db-01".into()],
            valid_after: 1_700_000_000,
            valid_before: 1_700_003_600,
            critical_options,
            extensions: vec![
                "permit-pty".into(),
                "permit-port-forwarding".into(),
                "permit-X11-forwarding".into(),
            ],
        },
        None,
    )
    .unwrap();
    let line = signed.line;
    assert!(line.starts_with("ecdsa-sha2-nistp256-cert-v01@openssh.com "));
    let parsed = parse_ssh_certificate(&line).unwrap();
    assert_eq!(parsed.key_type, "ecdsa-sha2-nistp256");
    assert_eq!(parsed.public_key_fingerprint, key.fingerprint);
    assert_eq!(parsed.serial, serial);
    assert_eq!(parsed.kind, SSH_CERT_USER as u32);
    assert_eq!(parsed.key_id, "alice@acme.test");
    assert_eq!(parsed.principals, vec!["deploy@web-01", "root@db-01"]);
    assert_eq!(parsed.valid_after, 1_700_000_000.0);
    assert_eq!(parsed.valid_before, 1_700_003_600.0);
    assert_eq!(
        parsed
            .critical_options
            .get("source-address")
            .map(String::as_str),
        Some("203.0.113.7/32")
    );
    // Lexical (byte) order: uppercase X sorts first.
    assert_eq!(
        parsed.extensions,
        vec![
            "permit-X11-forwarding",
            "permit-port-forwarding",
            "permit-pty"
        ]
    );
    assert!(parsed.signature_valid);
    assert_eq!(
        ssh_key_line(&parsed.signature_key, None).unwrap(),
        ssh_key_line(&ca.public_blob, None).unwrap()
    );
    // A flipped byte in the body breaks the signature.
    let (kind, data) = line.split_once(' ').unwrap();
    let mut blob = STANDARD.decode(data).unwrap();
    let at = blob.len() - 200;
    blob[at] ^= 1;
    assert!(
        !parse_ssh_certificate(&format!("{kind} {}", STANDARD.encode(blob)))
            .unwrap()
            .signature_valid
    );
}

#[test]
fn validates_host_addresses_and_logins() {
    let address = |value: &str| ssh_host_address(Some(&json!(value)));
    assert_eq!(
        address("Web-01.Prod.Example.com.").unwrap(),
        "web-01.prod.example.com"
    );
    assert_eq!(address("10.0.0.5").unwrap(), "10.0.0.5");
    assert_eq!(address("2001:db8::1").unwrap(), "2001:db8::1");
    assert!(address("*.example.com").is_err());
    assert!(address("bad host").is_err());
    assert!(address("127.1").is_err());
    assert!(address("fe80::1%eth0").is_err());
    let login = |value: &str| ssh_login(Some(&json!(value)));
    assert_eq!(login("deploy").unwrap(), "deploy");
    assert_eq!(login("_svc.ci-1").unwrap(), "_svc.ci-1");
    let long = "x".repeat(33);
    for bad in ["root@x", "1abc", "a b", "", long.as_str(), "dot."] {
        assert!(login(bad).is_err(), "{bad}");
    }
    assert_eq!(ssh_login_principal("deploy", "web-01"), "deploy@web-01");
}

#[test]
fn produces_certificates_and_revocation_lists_ssh_keygen_accepts() {
    let Some(keygen) = ssh_keygen() else {
        return;
    };
    let ca = authority();
    for kind in ["ed25519", "ecdsa", "rsa"] {
        let key = parse_ssh_public_key(Some(&key_value(&ssh_public_key(kind, "x"))), None).unwrap();
        let serial = ssh_serial();
        let mut critical_options = IndexMap::new();
        if kind == "ed25519" {
            critical_options.insert("force-command".to_owned(), "/usr/bin/true".to_owned());
        }
        let signed = sign_ssh_certificate(
            &ca,
            &SshCertificateSpec {
                key: key.clone(),
                serial,
                kind: if kind == "rsa" {
                    SSH_CERT_HOST as u32
                } else {
                    SSH_CERT_USER as u32
                },
                key_id: format!("key-{kind}"),
                principals: vec!["deploy@web-01".into()],
                valid_after: 1_700_000_000,
                valid_before: 4_100_000_000,
                critical_options,
                extensions: if kind == "rsa" {
                    Vec::new()
                } else {
                    vec!["permit-pty".into(), "permit-agent-forwarding".into()]
                },
            },
            None,
        )
        .unwrap();
        let other = sign_ssh_certificate(
            &ca,
            &SshCertificateSpec {
                key: key.clone(),
                serial: serial + 1,
                kind: SSH_CERT_USER as u32,
                key_id: "other".into(),
                principals: vec!["x".into()],
                valid_after: 0,
                valid_before: 4_100_000_000,
                critical_options: IndexMap::new(),
                extensions: Vec::new(),
            },
            None,
        )
        .unwrap();
        let krl = build_ssh_krl(&SshKrlInput {
            version: 7,
            generated_at: better_iam_server::utils::date_now(),
            comment: Some("test".into()),
            authorities: vec![KrlAuthoritySection {
                authority: ca.public_blob.clone(),
                serials: vec![serial, 99],
                key_ids: vec!["nobody".into()],
            }],
            keys: Vec::new(),
        });
        let directory = tempfile::tempdir().unwrap();
        let path = |name: &str| directory.path().join(name);
        std::fs::write(path("cert.pub"), format!("{}\n", signed.line)).unwrap();
        std::fs::write(path("other.pub"), format!("{}\n", other.line)).unwrap();
        std::fs::write(path("revoked.krl"), &krl).unwrap();
        let (status, output) = run_keygen(
            &keygen,
            &["-L".as_ref(), "-f".as_ref(), path("cert.pub").as_os_str()],
        );
        assert_eq!(status, 0, "{output}");
        assert!(
            output.contains(&format!("Key ID: \"key-{kind}\"")),
            "{output}"
        );
        assert!(output.contains(&format!("Serial: {serial}")), "{output}");
        assert!(output.contains("deploy@web-01"), "{output}");
        assert!(
            output.contains(if kind == "rsa" {
                "host certificate"
            } else {
                "user certificate"
            }),
            "{output}"
        );
        if kind == "ed25519" {
            assert!(output.contains("force-command /usr/bin/true"), "{output}");
        }
        let (_, revoked) = run_keygen(
            &keygen,
            &[
                "-Q".as_ref(),
                "-f".as_ref(),
                path("revoked.krl").as_os_str(),
                path("cert.pub").as_os_str(),
            ],
        );
        assert!(revoked.contains("REVOKED"), "{revoked}");
        let (status, fine) = run_keygen(
            &keygen,
            &[
                "-Q".as_ref(),
                "-f".as_ref(),
                path("revoked.krl").as_os_str(),
                path("other.pub").as_os_str(),
            ],
        );
        assert_eq!(status, 0, "{fine}");
        assert!(!fine.contains("REVOKED"), "{fine}");
    }
}

// --- ssh.ts --------------------------------------------------------------------------------------------------------

struct Setup {
    f: Org,
    ctx: Arc<better_iam_server::context::ServerContext>,
    authorities: EnsuredAuthorities,
    web: SshHost,
    db: SshHost,
    alice: String,
    alice_session: CredentialInput,
}

fn store(f: &Org) -> Arc<dyn IamStore> {
    f.iam.store.clone()
}

async fn tenant(s: &Setup) -> Tenant {
    s.ctx.tenant(&store(&s.f), &s.f.tenant_id).await.unwrap()
}

/// An enrolled host, as `createHost` and `enrollHost` leave it.
async fn enrolled_host(
    f: &Org,
    name: &str,
    addresses: &[&str],
    logins: &[&str],
    environment: &str,
    host_key: &str,
) -> SshHost {
    let key = parse_ssh_public_key(Some(&key_value(host_key)), None).unwrap();
    let now = f.now();
    let record = f
        .insert(
            "sshHosts",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "uniqueKey": name,
                "name": name,
                "addresses": addresses,
                "logins": logins,
                "labels": { "environment": environment },
                "status": "enrolled",
                "renewalTokenHash": "unused",
                "hostKey": ssh_key_line(&key.blob, None).unwrap(),
                "hostKeyFingerprint": key.fingerprint,
                "enrolledAt": now,
                "lastSeenAt": now,
                "createdAt": now,
                "createdBy": f.owner_id,
                "updatedAt": now,
            }),
        )
        .await;
    better_iam_server::port::decode(record).unwrap()
}

/// The staging deploy role: `ssh:login` on staging hosts as `deploy`, and port forwarding everywhere.
fn staging_deploy() -> Value {
    json!([
        {
            "effect": "allow",
            "actions": ["ssh:login"],
            "resources": ["ssh-login/*/deploy"],
            "conditions": { "StringEquals": { "resource.environment": "staging" } },
        },
        { "effect": "allow", "actions": ["ssh:port-forward"], "resources": ["ssh-host/*"] },
    ])
}

/// Acme with a verified domain (acme.test), the SSH authorities, two enrolled hosts (web-01 staging, db-01
/// production), and alice allowed `deploy` on staging hosts with port forwarding everywhere.
async fn setup() -> Setup {
    let f = organization(|options| options.ssh = Some(Toggle::Flag(true))).await;
    f.insert(
        "tenantDomains",
        json!({
            "id": better_iam_server::utils::id(),
            "tenantId": f.tenant_id,
            "domain": "Acme.test",
            "status": "verified",
        }),
    )
    .await;
    let ctx = f.iam.ctx.clone();
    let (job, tenant_id, owner_id) = (ctx.clone(), f.tenant_id.clone(), f.owner_id.clone());
    let authorities = f
        .iam
        .store
        .transaction(|tx| async move { ensure_authorities(&job, &tx, &tenant_id, &owner_id).await })
        .await
        .unwrap();
    let web = enrolled_host(
        &f,
        "web-01",
        &["web-01.acme.test", "10.0.0.5"],
        &["deploy", "root"],
        "staging",
        &ssh_public_key("ed25519", "root@web-01"),
    )
    .await;
    let db = enrolled_host(
        &f,
        "db-01",
        &[],
        &["postgres", "root"],
        "production",
        &ssh_public_key("ecdsa", "root@db-01"),
    )
    .await;
    let alice = f.member("alice").await;
    f.grant(&alice, staging_deploy()).await;
    let alice_session = f.sign_in(&alice).await;
    Setup {
        f,
        ctx,
        authorities,
        web,
        db,
        alice,
        alice_session,
    }
}

/// A user certificate for exactly `access`, signed and recorded as `issueCertificate` does.
async fn issue(
    s: &Setup,
    credential: &CredentialInput,
    access: &[(&SshHost, &[&str])],
) -> (SshCertificateRecord, String) {
    let principal: AuthenticatedPrincipal = s.f.iam.authenticate(credential).await.unwrap();
    let options = assert_ssh(&s.ctx).unwrap();
    let authority = active_authority(&store(&s.f), &s.f.tenant_id, "user")
        .await
        .unwrap();
    let key =
        parse_ssh_public_key(Some(&key_value(&ssh_public_key("ed25519", "x"))), None).unwrap();
    let now = s.f.now();
    let valid_before = now + 8.0 * HOUR;
    let principals: Vec<String> = access
        .iter()
        .flat_map(|(host, logins)| {
            logins
                .iter()
                .map(|login| ssh_login_principal(login, &host.name))
        })
        .collect();
    let extensions = vec![
        "permit-port-forwarding".to_owned(),
        "permit-pty".to_owned(),
        "permit-user-rc".to_owned(),
    ];
    let serial = ssh_serial();
    let key_id = certificate_key_id(&principal);
    let signed = sign_ssh_certificate(
        &open_authority(&s.ctx, &authority).unwrap(),
        &SshCertificateSpec {
            key: key.clone(),
            serial,
            kind: SSH_CERT_USER as u32,
            key_id: key_id.clone(),
            principals: principals.clone(),
            valid_after: ((now - options.clock_skew_ms) / 1000.0).floor() as u64,
            valid_before: (valid_before / 1000.0).floor() as u64,
            critical_options: IndexMap::new(),
            extensions: extensions.clone(),
        },
        None,
    )
    .unwrap();
    let record =
        s.f.insert(
            "sshCertificates",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": s.f.tenant_id,
                "uniqueKey": format!("{}:{serial}", authority.id),
                "kind": "user",
                "serial": serial.to_string(),
                "keyId": key_id,
                "authorityId": authority.id,
                "identityId": principal.identity.id,
                "sessionId": principal.session.id,
                "sessionKind": principal.session.kind,
                "mfa": principal.session.mfa,
                "principals": principals,
                "access": access
                    .iter()
                    .map(|(host, logins)| json!({ "host": host.name, "logins": logins }))
                    .collect::<Vec<_>>(),
                "extensions": extensions,
                "keyType": key.r#type,
                "publicKeyFingerprint": key.fingerprint,
                "validAfter": now - options.clock_skew_ms,
                "validBefore": valid_before,
                "issuedAt": now,
                "expiresAt": valid_before + options.record_retention_ms,
            }),
        )
        .await;
    (
        better_iam_server::port::decode(record).unwrap(),
        signed.line,
    )
}

/// The sweep result as JSON, numbers written as JavaScript writes them (the HTTP layer and `call` do).
async fn sweep(s: &Setup, input: Option<Value>) -> Value {
    let result = serde_json::to_value(
        sweep_ssh_certificates(&s.ctx, input.as_ref())
            .await
            .expect("sweep"),
    )
    .unwrap();
    serde_json::from_str(&better_iam_core::js::stringify(&result)).unwrap()
}

async fn certificate(s: &Setup, id: &str) -> SshCertificateRecord {
    better_iam_server::port::decode(
        store(&s.f)
            .get("sshCertificates", id)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

async fn set_member(f: &Org, collection: &str, id: &str, key: &str, value: Value) {
    let mut record = store(f).get(collection, id).await.unwrap().unwrap();
    record.insert(key.to_owned(), value);
    f.put(collection, record).await;
}

async fn remove(f: &Org, collection: &str, id: &str) {
    let (collection, id) = (collection.to_owned(), id.to_owned());
    f.iam
        .store
        .transaction(|tx| async move { tx.delete(&collection, &id).await })
        .await
        .unwrap();
}

#[test]
fn is_off_unless_the_ssh_option_is_set() {
    run(|| async {
        let f = organization(|_| {}).await;
        let ctx = f.iam.ctx.clone();
        let error = assert_ssh(&ctx).unwrap_err();
        assert_eq!((code(&error), error.status), ("FEATURE_DISABLED", 403));
        assert!(ssh_plugins(&f.iam.ctx.options).unwrap().is_empty());
        assert!(
            sweep_ssh_certificates(&ctx, None).await.is_err(),
            "the sweep needs the module"
        );
        let reference = better_iam_core::ResourceRef {
            tenant_id: f.tenant_id.clone(),
            kind: "ssh-login".into(),
            id: "web-01/deploy".into(),
        };
        assert!(
            resolve_ssh_resource(&ctx, &store(&f), &reference)
                .await
                .unwrap()
                .is_none()
        );
        // Invalid bounds are configuration errors.
        let error = resolve_ssh_options(Some(&Toggle::Options(SshOptions {
            max_user_certificate_ms: Some(1.0),
            ..SshOptions::default()
        })))
        .unwrap_err();
        assert_eq!(code(&error), "INVALID_CONFIG");
        assert_eq!(
            error.message,
            "ssh.maxUserCertificateMs must be an integer between 300000 and 604800000"
        );
        let error = resolve_ssh_options(Some(&Toggle::Options(SshOptions {
            record_retention_days: Some(1.5),
            ..SshOptions::default()
        })))
        .unwrap_err();
        assert_eq!(
            error.message,
            "ssh.recordRetentionDays must be an integer between 1 and 3650"
        );
        let resolved = resolve_ssh_options(Some(&Toggle::Flag(true)))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.max_user_certificate_ms, 24.0 * HOUR);
        assert_eq!(resolved.record_retention_ms, 90.0 * 24.0 * HOUR);
        assert_eq!(resolved.issuance_limit, 60.0);
        assert!(
            resolve_ssh_options(Some(&Toggle::Flag(false)))
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn sets_up_authorities_and_hands_hosts_and_members_their_trust() {
    run(|| async {
        let s = setup().await;
        assert_eq!(s.authorities.created, vec!["user", "host"]);
        assert_eq!(s.authorities.user.kind, "user");
        assert_eq!(s.authorities.user.status, "active");
        assert!(
            s.authorities
                .user
                .public_key
                .ends_with(" better-iam-user-ca")
        );
        assert!(
            s.authorities
                .host
                .public_key
                .ends_with(" better-iam-host-ca")
        );
        // Idempotent: a second setup creates nothing.
        let (job, tenant_id, owner_id) =
            (s.ctx.clone(), s.f.tenant_id.clone(), s.f.owner_id.clone());
        let again =
            s.f.iam
                .store
                .transaction(|tx| async move {
                    ensure_authorities(&job, &tx, &tenant_id, &owner_id).await
                })
                .await
                .unwrap();
        assert!(again.created.is_empty());
        assert_eq!(again.user.id, s.authorities.user.id);
        let listed = tenant_authorities(&store(&s.f), &s.f.tenant_id, None)
            .await
            .unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|item| item.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["user", "host"]
        );
        // The sealed key opens and signs as the published key.
        let signing = open_authority(&s.ctx, &s.authorities.host).unwrap();
        assert_eq!(
            ssh_key_line(&signing.public_blob, Some("better-iam-host-ca")).unwrap(),
            s.authorities.host.public_key
        );
        let host_key = stored_host_key(&s.web).unwrap();
        let signed = sign_ssh_certificate(
            &signing,
            &SshCertificateSpec {
                key: host_key,
                serial: ssh_serial(),
                kind: SSH_CERT_HOST as u32,
                key_id: "host:web-01".into(),
                principals: vec![
                    "web-01".into(),
                    "web-01.acme.test".into(),
                    "10.0.0.5".into(),
                ],
                valid_after: 1,
                valid_before: 4_100_000_000,
                critical_options: IndexMap::new(),
                extensions: Vec::new(),
            },
            Some("web-01"),
        )
        .unwrap();
        let parsed = parse_ssh_certificate(&signed.line).unwrap();
        assert!(parsed.signature_valid);
        assert_eq!(
            parsed.signature_key_fingerprint,
            s.authorities.host.fingerprint
        );
        assert!(signed.line.ends_with(" web-01"));

        let tenant = tenant(&s).await;
        let member = trust_bundle(&s.ctx, &store(&s.f), &tenant, "member")
            .await
            .unwrap();
        let host_key = s
            .authorities
            .host
            .public_key
            .split(' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            member["knownHosts"],
            json!(format!(
                "@cert-authority 10.0.0.5,db-01,web-01,web-01.acme.test {host_key} better-iam:{}\n",
                s.f.tenant_id
            ))
        );
        assert_eq!(
            member["trustedUserCaKeys"],
            json!(format!("{}\n", s.authorities.user.public_key))
        );
        assert_eq!(
            member["userAuthorities"][0]["id"],
            json!(s.authorities.user.id)
        );
        assert_eq!(
            member["userAuthorities"][0]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec!["id", "status", "publicKey", "fingerprint"]
        );
        assert_eq!(member["hostPatterns"], json!([]));
        // Anyone with the tenant ID: the keys, and no known_hosts line without configured patterns.
        let public = trust_bundle(&s.ctx, &store(&s.f), &tenant, "public")
            .await
            .unwrap();
        assert_eq!(public["knownHosts"], json!(""));
        assert_eq!(
            public["hostAuthorities"][0]["id"],
            json!(s.authorities.host.id)
        );

        // Each login gets a principals file holding its own principal on this host only.
        let files = principal_files(&s.web);
        assert_eq!(
            files.get("deploy").map(String::as_str),
            Some("deploy@web-01\n")
        );
        assert_eq!(files.get("root").map(String::as_str), Some("root@web-01\n"));
        assert_eq!(files.len(), 2);
        assert_eq!(s.db.logins, vec!["postgres", "root"]);
    });
}

#[test]
fn resolves_ssh_logins_and_hosts_for_the_decision_engine() {
    run(|| async {
        let s = setup().await;
        let resolve = |kind: &str, id: &str| better_iam_core::ResourceRef {
            tenant_id: s.f.tenant_id.clone(),
            kind: kind.into(),
            id: id.into(),
        };
        let reader = store(&s.f);
        let login = resolve_ssh_resource(&s.ctx, &reader, &resolve("ssh-login", "web-01/deploy"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(login.id, "web-01/deploy");
        assert_eq!(
            Value::Object(login.attributes.unwrap()),
            json!({ "environment": "staging", "host": "web-01", "login": "deploy" })
        );
        let host = resolve_ssh_resource(&s.ctx, &reader, &resolve("ssh-host", "db-01"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Value::Object(host.attributes.unwrap()),
            json!({ "environment": "production", "host": "db-01" })
        );
        for (kind, id, expected) in [
            ("ssh-login", "web-02/deploy", "Unknown SSH host"),
            ("ssh-login", "/deploy", "Unknown SSH host"),
            ("ssh-host", "nope", "Unknown SSH host"),
            ("ssh-login", "web-01/postgres", "Unknown login on this host"),
            ("ssh-login", "web-01", "Unknown SSH host"),
        ] {
            let error = resolve_ssh_resource(&s.ctx, &reader, &resolve(kind, id))
                .await
                .unwrap_err();
            assert_eq!(
                (code(&error), error.status, error.message.as_str()),
                ("NOT_FOUND", 404, expected)
            );
        }
        assert!(
            resolve_ssh_resource(&s.ctx, &reader, &resolve("documents", "x"))
                .await
                .unwrap()
                .is_none()
        );
        // The module contributes the two resource types.
        let plugins = ssh_plugins(&s.ctx.options).unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].id(), "better-iam:ssh");
        let types = plugins[0].resource_types();
        assert_eq!(
            types.keys().collect::<Vec<_>>(),
            vec!["ssh-login", "ssh-host"]
        );
        assert_eq!(
            types["ssh-host"].actions.clone().unwrap(),
            vec!["ssh:port-forward", "ssh:agent-forward", "ssh:x11-forward"]
        );
        assert_eq!(login_resource(&s.web, "root").id, "web-01/root");
        assert_eq!(host_resource(&s.web).kind, "ssh-host");
    });
}

#[test]
fn revokes_certificates_and_publishes_them_in_the_revocation_lists() {
    run(|| async {
        let s = setup().await;
        let (record, line) = issue(&s, &s.alice_session, &[(&s.web, &["deploy"])]).await;
        let tenant = tenant(&s).await;
        let reader = store(&s.f);
        let list = revocation_list(&s.ctx, &reader, &tenant, None)
            .await
            .unwrap();
        assert_eq!(list["kind"], json!("user"));
        assert_eq!(list["version"], json!(0));
        assert_eq!(list["revokedCertificates"], json!(0));
        assert_eq!(list["tenantActive"], json!(true));
        let krl = STANDARD.decode(list["krl"].as_str().unwrap()).unwrap();
        assert_eq!(&krl[..8], b"SSHKRL\n\0");

        let (job, revoked) = (s.ctx.clone(), record.clone());
        let marked =
            s.f.iam
                .store
                .transaction(|tx| async move {
                    let marked = mark_revoked(&job, &tx, &revoked, "revoked", "someone").await?;
                    // Idempotent: a second mark keeps the first.
                    let again = mark_revoked(&job, &tx, &marked, "superseded", "other").await?;
                    bump_revocation_version(&job, &tx, &revoked.tenant_id).await?;
                    Ok(again)
                })
                .await
                .unwrap();
        assert_eq!(marked.revocation_reason.as_deref(), Some("revoked"));
        assert_eq!(marked.revoked_by.as_deref(), Some("someone"));
        assert_eq!(marked.revoked_at, Some(s.f.now()));
        let stored = certificate(&s, &record.id).await;
        assert_eq!(stored.revocation_reason.as_deref(), Some("revoked"));
        assert!(
            live_certificates(&s.ctx, &reader, &json!({ "tenantId": s.f.tenant_id }))
                .await
                .unwrap()
                .is_empty()
        );
        let list = revocation_list(&s.ctx, &reader, &tenant, Some("user"))
            .await
            .unwrap();
        assert_eq!(list["version"], json!(1));
        assert_eq!(list["revokedCertificates"], json!(1));
        assert_eq!(list["revokedHostKeys"], json!(0));
        let krl = STANDARD.decode(list["krl"].as_str().unwrap()).unwrap();
        assert!(
            krl.windows(8)
                .any(|window| window == record.serial.parse::<u64>().unwrap().to_be_bytes()),
            "the KRL names the serial"
        );
        if let Some(keygen) = ssh_keygen() {
            let directory = tempfile::tempdir().unwrap();
            let path = |name: &str| directory.path().join(name);
            std::fs::write(path("cert.pub"), format!("{line}\n")).unwrap();
            std::fs::write(path("revoked.krl"), &krl).unwrap();
            let (_, output) = run_keygen(
                &keygen,
                &[
                    "-Q".as_ref(),
                    "-f".as_ref(),
                    path("revoked.krl").as_os_str(),
                    path("cert.pub").as_os_str(),
                ],
            );
            assert!(output.contains("REVOKED"), "{output}");
        }

        // A disabled host's key is published for clients to refuse; its name leaves the known_hosts line.
        set_member(&s.f, "sshHosts", &s.web.id, "status", json!("disabled")).await;
        let hosts = revocation_list(&s.ctx, &reader, &tenant, Some("host"))
            .await
            .unwrap();
        assert_eq!(hosts["kind"], json!("host"));
        assert_eq!(hosts["revokedHostKeys"], json!(1));
        assert_eq!(hosts["revokedCertificates"], json!(0));
        let member = trust_bundle(&s.ctx, &reader, &tenant, "member")
            .await
            .unwrap();
        let web_key = s.web.host_key.clone().unwrap();
        let known = member["knownHosts"].as_str().unwrap();
        assert!(
            known.contains(&format!("@revoked * {web_key} better-iam:revoked\n")),
            "{known}"
        );
        assert!(known.starts_with("@cert-authority db-01 "), "{known}");
    });
}

#[test]
fn sweeps_certificates_whose_holder_login_or_access_went_away() {
    run(|| async {
        let s = setup().await;
        let bob = s.f.member("bob").await;
        let carol = s.f.member("carol").await;
        let bob_role = s.f.grant(&bob, staging_deploy()).await;
        s.f.grant(&carol, staging_deploy()).await;
        let bob_session = s.f.sign_in(&bob).await;
        let carol_session = s.f.sign_in(&carol).await;
        let (alice_cert, _) = issue(&s, &s.alice_session, &[(&s.web, &["deploy"])]).await;
        let (bob_cert, _) = issue(&s, &bob_session, &[(&s.web, &["deploy"])]).await;
        assert_eq!(
            sweep(&s, None).await,
            json!({ "examined": 2, "revoked": 0, "byReason": {} })
        );

        // Alice's account is disabled: the revocation list refuses her certificate even before the sweep runs.
        set_member(&s.f, "identities", &s.alice, "status", json!("disabled")).await;
        let tenant = tenant(&s).await;
        let list = revocation_list(&s.ctx, &store(&s.f), &tenant, None)
            .await
            .unwrap();
        assert_eq!(list["revokedCertificates"], json!(1));
        // Bob loses the grant: his certificate no longer matches policy.
        let binding =
            s.f.find(
                "bindings",
                Filter::new()
                    .eq("subjectId", bob.clone())
                    .eq("roleId", bob_role),
            )
            .await;
        remove(&s.f, "bindings", binding[0]["id"].as_str().unwrap()).await;

        let swept = sweep(&s, Some(json!({ "tenantId": s.f.tenant_id }))).await;
        assert_eq!(
            swept,
            json!({ "examined": 2, "revoked": 2, "byReason": { "identity-inactive": 1, "access-changed": 1 } })
        );
        assert_eq!(
            certificate(&s, &alice_cert.id)
                .await
                .revocation_reason
                .as_deref(),
            Some("identity-inactive")
        );
        let bob_record = certificate(&s, &bob_cert.id).await;
        assert_eq!(
            bob_record.revocation_reason.as_deref(),
            Some("access-changed")
        );
        assert_eq!(
            bob_record.revoked_by.as_deref(),
            Some("deployment-operator")
        );
        let settings = load_ssh_settings(&s.ctx, &store(&s.f), &s.f.tenant_id)
            .await
            .unwrap();
        assert_eq!(settings.revocation_version, 1.0);
        let events =
            s.f.find(
                "audit",
                Filter::new()
                    .eq("tenantId", s.f.tenant_id.clone())
                    .eq("action", "ssh:certificate:revoke"),
            )
            .await;
        assert_eq!(events.len(), 2);
        let bob_event = events
            .iter()
            .find(|event| event["resourceId"] == json!(format!("ssh/certificates/{}", bob_cert.id)))
            .expect("bob's revocation");
        assert_eq!(bob_event["actorId"], json!("deployment-operator"));
        assert_eq!(bob_event["outcome"], json!("allow"));
        assert_eq!(
            bob_event["metadata"],
            json!({ "reason": "access-changed", "serial": bob_cert.serial, "identityId": bob })
        );

        // A login removed from the host takes the certificates naming it.
        let (carol_cert, _) = issue(&s, &carol_session, &[(&s.web, &["deploy"])]).await;
        set_member(&s.f, "sshHosts", &s.web.id, "logins", json!(["root"])).await;
        assert_eq!(
            sweep(&s, Some(json!({ "tenantId": s.f.tenant_id }))).await["byReason"],
            json!({ "access-changed": 1 })
        );
        assert!(certificate(&s, &carol_cert.id).await.revoked_at.is_some());

        // A certificate whose session ended goes with it; the revocation list refuses it at once.
        set_member(
            &s.f,
            "sshHosts",
            &s.web.id,
            "logins",
            json!(["deploy", "root"]),
        )
        .await;
        let dave = s.f.member("dave").await;
        s.f.grant(&dave, staging_deploy()).await;
        let dave_session = s.f.sign_in(&dave).await;
        let (dave_cert, _) = issue(&s, &dave_session, &[(&s.web, &["deploy"])]).await;
        remove(&s.f, "sessions", dave_cert.session_id.as_deref().unwrap()).await;
        let list = revocation_list(&s.ctx, &store(&s.f), &tenant, None)
            .await
            .unwrap();
        assert_eq!(list["revokedCertificates"], json!(4));
        assert_eq!(
            sweep(&s, None).await,
            json!({ "examined": 1, "revoked": 1, "byReason": { "session-ended": 1 } })
        );
        // Forwarding: a certificate carrying port forwarding loses it when a named host stops allowing it.
        let erin = s.f.member("erin").await;
        s.f.grant(
            &erin,
            json!([{ "effect": "allow", "actions": ["ssh:login"], "resources": ["ssh-login/*/deploy"] }]),
        )
        .await;
        let erin_session = s.f.sign_in(&erin).await;
        let (erin_cert, _) = issue(&s, &erin_session, &[(&s.web, &["deploy"])]).await;
        assert_eq!(
            sweep(&s, None).await["byReason"],
            json!({ "access-changed": 1 })
        );
        assert_eq!(
            certificate(&s, &erin_cert.id)
                .await
                .revocation_reason
                .as_deref(),
            Some("access-changed")
        );
    });
}

#[test]
fn revokes_every_user_certificate_while_the_organization_is_suspended() {
    run(|| async {
        let s = setup().await;
        issue(&s, &s.alice_session, &[(&s.web, &["deploy"])]).await;
        set_member(
            &s.f,
            "tenants",
            &s.f.tenant_id,
            "status",
            json!("suspended"),
        )
        .await;
        let tenant = tenant(&s).await;
        assert!(!tenant_active(&s.ctx, &store(&s.f), &tenant).await.unwrap());
        let list = revocation_list(&s.ctx, &store(&s.f), &tenant, None)
            .await
            .unwrap();
        assert_eq!(list["tenantActive"], json!(false));
        assert_eq!(list["revokedCertificates"], json!(1));
        // The sweep leaves them alone: they return with the organization.
        let swept = sweep(&s, None).await;
        assert_eq!(swept["revoked"], json!(0));
        set_member(&s.f, "tenants", &s.f.tenant_id, "status", json!("active")).await;
        let tenant = tenant_of(&s).await;
        let list = revocation_list(&s.ctx, &store(&s.f), &tenant, None)
            .await
            .unwrap();
        assert_eq!(list["revokedCertificates"], json!(0));
    });
}

async fn tenant_of(s: &Setup) -> Tenant {
    tenant(s).await
}

#[test]
fn never_lets_the_platform_root_override_keep_an_organization_certificate() {
    run(|| async {
        let s = setup().await;
        let (record, _) = issue(&s, &s.f.root_credential, &[(&s.web, &["deploy"])]).await;
        assert_eq!(
            sweep(&s, None).await,
            json!({ "examined": 1, "revoked": 1, "byReason": { "access-changed": 1 } })
        );
        assert_eq!(
            certificate(&s, &record.id)
                .await
                .revocation_reason
                .as_deref(),
            Some("access-changed")
        );
    });
}

#[test]
fn keeps_the_host_authority_to_names_the_organization_owns_unique_per_host() {
    run(|| async {
        let s = setup().await;
        let domains = verified_domains(&store(&s.f), &s.f.tenant_id)
            .await
            .unwrap();
        assert_eq!(domains, vec!["acme.test"]);
        // `*` and names outside the verified domains are refused as patterns.
        for patterns in [json!(["*"]), json!(["*.github.com"]), json!(["github.com"])] {
            let error = host_pattern_list(Some(&patterns), &domains).unwrap_err();
            assert_eq!((code(&error), error.status), ("HOST_OUTSIDE_PATTERNS", 400));
        }
        assert_eq!(
            host_pattern_list(Some(&json!(["*"])), &domains)
                .unwrap_err()
                .message,
            "Pattern * must end in a verified domain of this organization or fix an address prefix"
        );
        for invalid in [
            json!("*.acme.test"),
            json!([1]),
            json!(["a b"]),
            json!(vec!["x"; 17]),
        ] {
            assert_eq!(
                code(&host_pattern_list(Some(&invalid), &domains).unwrap_err()),
                "INVALID_INPUT"
            );
        }
        assert_eq!(
            host_pattern_list(Some(&json!(["!x.acme.test"])), &domains)
                .unwrap_err()
                .message,
            "hostPatterns needs at least one pattern that is not negated"
        );
        let patterns = host_pattern_list(
            Some(&json!([
                "*.Acme.test",
                "web-*",
                "db-*",
                "10.0.0.*",
                "!bastion.acme.test",
                "*.acme.test",
                "fd00:1:*",
                "192.168.1.10",
            ])),
            &domains,
        )
        .unwrap();
        assert_eq!(
            patterns,
            vec![
                "*.acme.test",
                "web-*",
                "db-*",
                "10.0.0.*",
                "!bastion.acme.test",
                "fd00:1:*",
                "192.168.1.10"
            ]
        );
        assert!(
            host_pattern_list(Some(&json!([])), &domains)
                .unwrap()
                .is_empty()
        );

        // Without patterns: single labels, private addresses and names under the verified domains.
        let mut settings = load_ssh_settings(&s.ctx, &store(&s.f), &s.f.tenant_id)
            .await
            .unwrap();
        let names = |list: &[&str]| {
            list.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        assert_vouchable(
            &settings,
            &domains,
            &names(&[
                "web-01",
                "web-01.acme.test",
                "10.0.0.5",
                "fd00::1",
                "acme.test",
            ]),
        )
        .unwrap();
        let error = assert_vouchable(
            &settings,
            &domains,
            &names(&["github.com", "localhost", "8.8.8.8", "web-02"]),
        )
        .unwrap_err();
        assert_eq!(code(&error), "HOST_OUTSIDE_PATTERNS");
        assert_eq!(
            error.message,
            "github.com, localhost, 8.8.8.8 is outside the names this organization can vouch for (verify its domain or set hostPatterns)"
        );
        // With patterns: every name must match them as well, and a negated pattern always wins.
        settings.host_patterns = patterns;
        assert_vouchable(
            &settings,
            &domains,
            &names(&["web-02", "x.acme.test", "10.0.0.9"]),
        )
        .unwrap();
        for outside in ["bastion.acme.test", "github.com", "mail-01", "10.0.1.1"] {
            assert!(
                assert_vouchable(&settings, &domains, &names(&[outside])).is_err(),
                "{outside}"
            );
        }
        // A pattern matching a foreign name never makes it vouchable.
        settings.host_patterns = vec!["*".into()];
        assert!(assert_vouchable(&settings, &domains, &names(&["github.com"])).is_err());
        assert!(assert_vouchable(&settings, &domains, &names(&["8.8.8.8"])).is_err());
        settings.host_patterns = vec!["8.8.*".into()];
        assert_vouchable(&settings, &domains, &names(&["8.8.8.8"])).unwrap();

        assert!(known_hosts_match(&["*.ACME.test".into()], "Web.acme.test"));
        assert!(!known_hosts_match(
            &["*.acme.test".into(), "!bastion.acme.test".into()],
            "bastion.acme.test"
        ));
        assert!(!known_hosts_match(
            &["!bastion.acme.test".into()],
            "web.acme.test"
        ));
        for (address, private) in [
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("172.32.0.1", false),
            ("192.168.0.1", true),
            ("169.254.1.1", true),
            ("100.64.0.1", true),
            ("100.128.0.1", false),
            ("127.0.0.1", true),
            ("8.8.8.8", false),
            ("::1", true),
            ("fd12::1", true),
            ("fe80::1", true),
            ("2001:db8::1", false),
            ("web-01", false),
        ] {
            assert_eq!(private_address(address), private, "{address}");
        }

        // Another host's names are taken.
        let reader = store(&s.f);
        let error = assert_names_free(
            &reader,
            &s.f.tenant_id,
            &names(&["web-02", "web-01.acme.test"]),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            (code(&error), error.status, error.message.as_str()),
            (
                "HOST_NAME_TAKEN",
                409,
                "Host web-01 already uses web-01.acme.test"
            )
        );
        assert_names_free(
            &reader,
            &s.f.tenant_id,
            &names(&["web-01", "10.0.0.5"]),
            Some(&s.web.id),
        )
        .await
        .unwrap();
        // An authority key or another host's key is never accepted as a host key.
        let authority_key =
            parse_ssh_public_key(Some(&json!(s.authorities.user.public_key)), None).unwrap();
        let error = assert_host_key_free(&reader, &s.f.tenant_id, "spare", &authority_key)
            .await
            .unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "An authority key cannot be a host key")
        );
        let web_key = stored_host_key(&s.web).unwrap();
        let error = assert_host_key_free(&reader, &s.f.tenant_id, "spare", &web_key)
            .await
            .unwrap_err();
        assert_eq!((code(&error), error.status), ("HOST_KEY_IN_USE", 409));
        assert_host_key_free(&reader, &s.f.tenant_id, &s.web.id, &web_key)
            .await
            .unwrap();
        let security_key =
            parse_ssh_public_key(Some(&json!(ssh_public_key("sk-ed25519", "x"))), None).unwrap();
        assert_eq!(
            assert_host_key_free(&reader, &s.f.tenant_id, "spare", &security_key)
                .await
                .unwrap_err()
                .message,
            "Host keys cannot be security keys"
        );
        let found = host_by_name(&reader, &s.f.tenant_id, "db-01")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, s.db.id);
        assert!(
            host_by_name(&reader, &s.f.tenant_id, "nope")
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn validates_host_names_and_labels() {
    let name = |value: Value| ssh_host_name(Some(&value));
    assert_eq!(name(json!(" Web-01.Corp ")).unwrap(), "web-01.corp");
    for bad in [
        json!("web_01"),
        json!("-web"),
        json!("web..01"),
        json!("127.1"),
        json!("a/b"),
        json!(""),
        json!("x".repeat(129)),
        json!(5),
    ] {
        assert_eq!(
            code(&name(bad.clone()).unwrap_err()),
            "INVALID_INPUT",
            "{bad}"
        );
    }
    assert!(name(json!("x".repeat(128))).is_ok());
    let labels = ssh_labels(Some(&json!({ "environment": "staging", "team": "web" }))).unwrap();
    assert_eq!(
        labels.get("environment").map(String::as_str),
        Some("staging")
    );
    assert!(ssh_labels(None).unwrap().is_empty());
    assert_eq!(
        ssh_labels(Some(&json!(null))).unwrap_err().message,
        "labels must be an object of strings"
    );
    assert!(ssh_labels(Some(&json!(["a"]))).is_err());
    assert_eq!(
        ssh_labels(Some(&json!({ "host": "x" })))
            .unwrap_err()
            .message,
        "Invalid or reserved label name host"
    );
    assert_eq!(
        ssh_labels(Some(&json!({ "env": 1 }))).unwrap_err().message,
        "Label env must be a string of at most 256 characters"
    );
    assert!(ssh_labels(Some(&json!({ "env": "a\nb" }))).is_err());
    assert!(ssh_labels(Some(&json!({ "env": "x".repeat(257) }))).is_err());
    let many: serde_json::Map<String, Value> = (0..33)
        .map(|index| (format!("l{index}"), json!("x")))
        .collect();
    assert_eq!(
        ssh_labels(Some(&Value::Object(many))).unwrap_err().message,
        "A host has at most 32 labels"
    );
}

#[test]
fn stores_settings_capped_by_the_deployment() {
    run(|| async {
        let f = organization(|options| {
            options.ssh = Some(Toggle::Options(SshOptions {
                max_user_certificate_ms: Some(12.0 * HOUR),
                ..SshOptions::default()
            }))
        })
        .await;
        let ctx = f.iam.ctx.clone();
        let defaults = load_ssh_settings(&ctx, &store(&f), &f.tenant_id)
            .await
            .unwrap();
        assert_eq!(defaults.default_certificate_ms, 8.0 * HOUR);
        assert_eq!(defaults.max_certificate_ms, 12.0 * HOUR);
        assert_eq!(defaults.revocation_version, 0.0);
        assert!(
            store(&f)
                .get("sshSettings", &f.tenant_id)
                .await
                .unwrap()
                .is_none()
        );
        let (job, tenant_id) = (ctx.clone(), f.tenant_id.clone());
        f.iam
            .store
            .transaction(|tx| async move {
                let settings = load_ssh_settings(&job, &tx, &tenant_id).await?;
                save_ssh_settings(
                    &tx,
                    &SshSettings {
                        max_certificate_ms: 20.0 * HOUR,
                        default_certificate_ms: 16.0 * HOUR,
                        require_mfa: true,
                        ..settings
                    },
                )
                .await?;
                bump_revocation_version(&job, &tx, &tenant_id).await?;
                bump_revocation_version(&job, &tx, &tenant_id).await
            })
            .await
            .unwrap();
        let stored = store(&f)
            .get("sshSettings", &f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored["revocationVersion"], json!(2));
        assert_eq!(stored["requireMfa"], json!(true));
        // A deployment that lowered its maximum caps what tenants stored earlier.
        let loaded = load_ssh_settings(&ctx, &store(&f), &f.tenant_id)
            .await
            .unwrap();
        assert_eq!(loaded.max_certificate_ms, 12.0 * HOUR);
        assert_eq!(loaded.default_certificate_ms, 12.0 * HOUR);
        assert!(loaded.require_mfa);
        assert_eq!(loaded.revocation_version, 2.0);
    });
}

#[test]
fn names_the_holder_in_certificate_key_ids() {
    run(|| async {
        let s = setup().await;
        let principal = s.f.iam.authenticate(&s.alice_session).await.unwrap();
        assert_eq!(
            certificate_key_id(&principal),
            format!("alice@acme.test ({})", s.alice)
        );
        let mut odd = principal.clone();
        odd.identity.email = None;
        odd.identity.name = "Zoë \"Z\" 😀".into();
        odd.session.original_identity_id = Some("admin-1".into());
        assert_eq!(
            certificate_key_id(&odd),
            format!("Zo_ _Z_ __ ({}) via admin-1", s.alice)
        );
        odd.session.agent_id = Some("agent-7".into());
        assert!(certificate_key_id(&odd).ends_with(" via agent agent-7"));
        odd.identity.name = "x".repeat(300);
        assert_eq!(certificate_key_id(&odd).len(), 256);
        // Grant deadlines: a standing grant sets no limit.
        let horizon = s.f.now() + 8.0 * HOUR;
        let deadline = grant_deadline(&s.ctx, &store(&s.f), &principal, &s.f.tenant_id, horizon)
            .await
            .unwrap();
        assert_eq!(deadline, horizon);
    });
}
