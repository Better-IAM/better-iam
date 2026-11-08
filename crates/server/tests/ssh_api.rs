//! The SSH certificate authority's API group (`api/ssh.ts`), ported from tests/ssh.test.ts. Keys are generated
//! in-process as tests/support/ssh.ts does, and certificates are read back with a parser of the OpenSSH certificate
//! format written here (as `parseSshCertificate` reads them). The suites that run the authority need the `ssh` and
//! `ssh-ca` modules (`ssh.ts`, `ssh-ca.ts`: another unit) and are ignored until those are ported; the checks every
//! route makes before it reaches them run now.

mod organization_fixture;

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use better_iam_core::{CredentialInput, Filter, IamError};
use better_iam_server::options::{AuthorizationRequest, DomainOptions, ResourceTarget, Toggle};
use bytes::Bytes;
use http::Method;
use organization_fixture::{ORIGIN, Org, bearer, body, code, fails, ok, organization, run};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const HOUR: f64 = 3_600_000.0;

// --- keys and certificates ---------------------------------------------------------------------------------------

fn write(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn mpint(value: &[u8]) -> Vec<u8> {
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        let mut out = vec![0];
        out.extend_from_slice(value);
        out
    } else {
        value.to_vec()
    }
}

/// `sshPublicKey(type, comment)`: a fresh OpenSSH public key line generated in-process.
fn ssh_public_key(kind: &str, comment: &str) -> String {
    match kind {
        "ed25519" | "sk-ed25519" => {
            let secret: [u8; 32] = rand::random();
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            let raw = key.verifying_key().to_bytes();
            let name = if kind == "ed25519" {
                "ssh-ed25519"
            } else {
                "sk-ssh-ed25519@openssh.com"
            };
            let blob = if kind == "ed25519" {
                write(&[name.as_bytes(), &raw])
            } else {
                write(&[name.as_bytes(), &raw, b"ssh:"])
            };
            format!("{name} {} {comment}", STANDARD.encode(blob))
        }
        "ecdsa" => {
            let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
            let point = key.verifying_key().to_encoded_point(false);
            let blob = write(&[b"ecdsa-sha2-nistp256", b"nistp256", point.as_bytes()]);
            format!("ecdsa-sha2-nistp256 {} {comment}", STANDARD.encode(blob))
        }
        _ => {
            use rsa::traits::PublicKeyParts;
            let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa key");
            let blob = write(&[
                b"ssh-rsa",
                &mpint(&key.e().to_bytes_be()),
                &mpint(&key.n().to_bytes_be()),
            ]);
            format!("ssh-rsa {} {comment}", STANDARD.encode(blob))
        }
    }
}

fn key(kind: &str) -> String {
    ssh_public_key(kind, "test@example")
}

/// `SHA256:` plus the unpadded base64 SHA-256 of a key blob.
fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// The fingerprint of a public key line.
fn line_fingerprint(line: &str) -> String {
    let data = line.split(' ').nth(1).expect("key data");
    fingerprint(&STANDARD.decode(data).expect("base64"))
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    fn take(&mut self, count: usize) -> &'a [u8] {
        let slice = &self.data[self.position..self.position + count];
        self.position += count;
        slice
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }
    fn string(&mut self) -> &'a [u8] {
        let length = self.u32() as usize;
        self.take(length)
    }
    fn text(&mut self) -> String {
        String::from_utf8(self.string().to_vec()).unwrap()
    }
    fn done(&self) -> bool {
        self.position >= self.data.len()
    }
}

#[derive(Debug)]
struct ParsedCertificate {
    kind_name: String,
    public_key_fingerprint: String,
    kind: u32,
    key_id: String,
    principals: Vec<String>,
    valid_before: u64,
    critical_options: Vec<(String, String)>,
    extensions: Vec<String>,
    signature_key_fingerprint: String,
    signature_valid: bool,
}

fn options_of(data: &[u8], critical: bool) -> Vec<(String, String)> {
    let mut reader = Reader::new(data);
    let mut out = Vec::new();
    while !reader.done() {
        let name = reader.text();
        let value = reader.string();
        let value = if critical && !value.is_empty() {
            Reader::new(value).text()
        } else {
            String::new()
        };
        out.push((name, value));
    }
    out
}

/// `parseSshCertificate(line)`.
fn parse_certificate(line: &str) -> ParsedCertificate {
    let mut parts = line.split_whitespace();
    let type_name = parts.next().unwrap().to_owned();
    let blob = STANDARD.decode(parts.next().unwrap()).unwrap();
    let base = type_name.strip_suffix("-cert-v01@openssh.com").unwrap();
    let key_type = if base.starts_with("sk-") {
        format!("{base}@openssh.com")
    } else {
        base.to_owned()
    };
    let mut cert = Reader::new(&blob);
    assert_eq!(cert.text(), type_name);
    cert.string(); // nonce
    let key_start = cert.position;
    let fields = match key_type.as_str() {
        "ssh-ed25519" => 1,
        "sk-ecdsa-sha2-nistp256@openssh.com" => 3,
        _ => 2,
    };
    for _ in 0..fields {
        cert.string();
    }
    let mut key_blob = write(&[key_type.as_bytes()]);
    key_blob.extend_from_slice(&blob[key_start..cert.position]);
    let _serial = cert.u64();
    let kind = cert.u32();
    let key_id = cert.text();
    let mut principal_reader = Reader::new(cert.string());
    let mut principals = Vec::new();
    while !principal_reader.done() {
        principals.push(principal_reader.text());
    }
    let _valid_after = cert.u64();
    let valid_before = cert.u64();
    let critical_options = options_of(cert.string(), true);
    let extensions = options_of(cert.string(), false)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    cert.string(); // reserved
    let signature_key = cert.string();
    let body_length = cert.position;
    let mut signature = Reader::new(cert.string());
    assert!(cert.done(), "unexpected data after the certificate");
    let algorithm = signature.text();
    let value = signature.string();
    let mut ca = Reader::new(signature_key);
    let signature_valid = algorithm == "ssh-ed25519" && ca.text() == "ssh-ed25519" && {
        let raw: [u8; 32] = ca.string().try_into().unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(value).unwrap();
        key.verify_strict(&blob[..body_length], &signature).is_ok()
    };
    ParsedCertificate {
        kind_name: type_name,
        public_key_fingerprint: fingerprint(&key_blob),
        kind,
        key_id,
        principals,
        valid_before,
        critical_options,
        extensions,
        signature_key_fingerprint: fingerprint(signature_key),
        signature_valid,
    }
}

/// The system's ssh-keygen, when installed.
fn ssh_keygen() -> Option<String> {
    for candidate in [
        "ssh-keygen",
        "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe",
    ] {
        if Command::new(candidate).arg("-?").output().is_ok() {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn run_keygen(binary: &str, args: &[&str]) -> (i32, String) {
    let output = Command::new(binary)
        .args(args)
        .output()
        .expect("ssh-keygen");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(1), text)
}

// --- the fixture -------------------------------------------------------------------------------------------------

fn s(value: &Value) -> String {
    value.as_str().expect("a string").to_owned()
}

struct Ssh {
    f: Org,
    setup: Value,
    web: Value,
    db: Value,
    web_setup: Value,
    db_setup: Value,
    web_host_key: String,
    alice: String,
    alice_session: CredentialInput,
    role: String,
}

impl Ssh {
    fn tenant(&self) -> &str {
        &self.f.tenant_id
    }
    fn owner(&self) -> &CredentialInput {
        &self.f.owner_credential
    }
}

fn with_ssh(options: &mut better_iam_server::options::BetterIamOptions, dns: Dns) {
    options.ssh = Some(Toggle::Flag(true));
    options.domains = Some(DomainOptions {
        resolve_txt: Some(Arc::new(move |hostname| {
            let records = dns.lock().unwrap().get(&hostname).cloned();
            Box::pin(async move { Ok(records.unwrap_or_default()) })
        })),
        ..DomainOptions::default()
    });
}

type Dns = Arc<Mutex<HashMap<String, Vec<Vec<String>>>>>;

async fn create_role(f: &Org, name: &str, statements: Value) -> String {
    let role = ok(f
        .iam
        .api
        .roles
        .create(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": name,
                "document": { "version": 1, "statements": statements },
            })),
        )
        .await);
    s(&role["id"])
}

async fn bind(f: &Org, role_id: &str, subject_id: &str, extra: Value) {
    let mut input = json!({
        "tenantId": f.tenant_id,
        "roleId": role_id,
        "subjectType": "identity",
        "subjectId": subject_id,
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        input[key] = value;
    }
    ok(f.iam
        .api
        .bindings
        .create(&f.owner_credential, body(input))
        .await);
}

/// Acme with a verified domain (acme.test), the SSH CA set up, two enrolled hosts (web-01 staging, db-01
/// production), and alice allowed `deploy` on staging hosts with port forwarding everywhere.
async fn setup() -> Ssh {
    let dns: Dns = Arc::default();
    let zone = dns.clone();
    let f = organization(move |options| with_ssh(options, zone)).await;
    let claim = ok(f
        .iam
        .api
        .domains
        .add(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "domain": "acme.test" })),
        )
        .await);
    dns.lock().unwrap().insert(
        s(&claim["dnsRecord"]["name"]),
        vec![vec![s(&claim["dnsRecord"]["value"])]],
    );
    ok(f.iam
        .api
        .domains
        .verify(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "domainId": claim["id"] })),
        )
        .await);
    let ssh = &f.iam.api.ssh;
    let setup = ok(ssh
        .setup(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id })),
        )
        .await);
    let web = ok(ssh
        .create_host(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "web-01",
                "addresses": ["web-01.acme.test", "10.0.0.5"],
                "logins": ["deploy", "root"],
                "labels": { "environment": "staging" },
            })),
        )
        .await);
    let db = ok(ssh
        .create_host(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "db-01",
                "logins": ["postgres", "root"],
                "labels": { "environment": "production" },
            })),
        )
        .await);
    let web_host_key = ssh_public_key("ed25519", "root@web-01");
    let web_setup = ok(ssh
        .enroll_host(body(
            json!({ "joinToken": web["joinToken"], "publicKey": web_host_key }),
        ))
        .await);
    let db_setup = ok(ssh
        .enroll_host(body(json!({
            "joinToken": db["joinToken"],
            "publicKey": ssh_public_key("ecdsa", "root@db-01"),
        })))
        .await);
    let alice = f.member("alice").await;
    let role = create_role(
        &f,
        "Staging deploy",
        json!([
            {
                "effect": "allow",
                "actions": ["ssh:login"],
                "resources": ["ssh-login/*/deploy"],
                "conditions": { "StringEquals": { "resource.environment": "staging" } },
            },
            { "effect": "allow", "actions": ["ssh:port-forward"], "resources": ["ssh-host/*"] },
        ]),
    )
    .await;
    bind(&f, &role, &alice, json!({})).await;
    let alice_session = f.sign_in(&alice).await;
    Ssh {
        f,
        setup,
        web,
        db,
        web_setup,
        db_setup,
        web_host_key,
        alice,
        alice_session,
        role,
    }
}

/// The tenant's audit events (`audit.list`).
async fn audit_of(f: &Org) -> Vec<Value> {
    let events = ok(f
        .iam
        .api
        .audit
        .list(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "limit": 500 })),
        )
        .await);
    match events {
        Value::Array(items) => items,
        other => other["events"].as_array().cloned().unwrap_or_default(),
    }
}

fn has_event(
    events: &[Value],
    action: &str,
    outcome: &str,
    check: impl Fn(&Value) -> bool,
) -> bool {
    events.iter().any(|event| {
        event["action"] == json!(action) && event["outcome"] == json!(outcome) && check(event)
    })
}

async fn issue(t: &Ssh, credential: &CredentialInput, input: Value) -> Result<Value, IamError> {
    let mut request = json!({ "tenantId": t.tenant() });
    for (key, value) in input.as_object().cloned().unwrap_or_default() {
        request[key] = value;
    }
    t.f.iam
        .api
        .ssh
        .issue_certificate(credential, body(request))
        .await
        .map(|reply| reply.into_value().unwrap())
}

async fn revocation(t: &Ssh, input: Value) -> Value {
    let mut request = json!({ "tenantId": t.tenant() });
    for (key, value) in input.as_object().cloned().unwrap_or_default() {
        request[key] = value;
    }
    ok(t.f.iam.api.ssh.revocation_list(body(request)).await)
}

async fn sync(t: &Ssh, input: Value) -> Result<Value, IamError> {
    t.f.iam
        .api
        .ssh
        .sync_host(body(input))
        .await
        .map(|reply| reply.into_value().unwrap())
}

fn error_code(result: Result<Value, IamError>) -> String {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error.code,
    }
}

/// `POST {basePath}/ssh/{path}` with plain JSON and an optional bearer token.
async fn post(f: &Org, path: &str, input: Value, token: Option<&str>) -> (u16, Value) {
    let mut request = http::Request::builder()
        .method(Method::POST)
        .uri(format!("{ORIGIN}/api/iam/ssh/{path}"))
        .header("content-type", "application/json")
        .header("x-better-iam", "1");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = f
        .iam
        .handler(request.body(Bytes::from(input.to_string())).unwrap())
        .await;
    let status = response.status().as_u16();
    (
        status,
        serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    )
}

// --- what every route checks before the authority -----------------------------------------------------------------

#[test]
fn validates_input_and_finds_records_before_reaching_the_authority() {
    run(|| async {
        let f = organization(|_| {}).await;
        let ssh = &f.iam.api.ssh;
        let owner = &f.owner_credential;
        // The ssh-login type and ssh:login are not in the catalog while the option is off.
        let refused = fails(
            f.iam
                .api
                .roles
                .create(
                    owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": "x",
                        "document": {
                            "version": 1,
                            "statements": [{ "effect": "allow", "actions": ["ssh:login"], "resources": ["*"] }],
                        },
                    })),
                )
                .await,
        );
        assert_eq!(code(&refused), "INVALID_ACTION");
        // The authority kind is checked before anything else.
        let error = fails(
            ssh.rotate_authority(
                owner,
                body(json!({ "tenantId": f.tenant_id, "kind": "admin" })),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str(), error.status),
            ("INVALID_INPUT", "kind must be 'user' or 'host'", 400)
        );
        let error = fails(ssh.setup(owner, body(json!({}))).await);
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Invalid tenantId")
        );
        // Host routes name the host in the resource they authorize on, so an unknown host is NOT_FOUND first.
        let unknown = json!({ "tenantId": f.tenant_id, "hostId": "nope" });
        assert_eq!(
            fails(ssh.get_host(owner, body(unknown.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.disable_host(owner, body(unknown.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.delete_host(owner, body(unknown.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.reset_join_token(owner, body(unknown.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.who_can_login(owner, body(unknown.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.update_host(owner, body(unknown)).await).code,
            "NOT_FOUND"
        );
        let error = fails(
            ssh.update_host(owner, body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Invalid hostId")
        );
        let missing = json!({ "tenantId": f.tenant_id, "authorityId": "nope" });
        assert_eq!(
            fails(ssh.activate_authority(owner, body(missing.clone())).await).code,
            "NOT_FOUND"
        );
        assert_eq!(
            fails(ssh.retire_authority(owner, body(missing)).await).code,
            "NOT_FOUND"
        );
        let error = fails(
            ssh.activate_authority(owner, body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(error.message, "Invalid authorityId");
    });
}

// --- tests/ssh.test.ts -------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs ssh.ts assertSsh (ssh unit)"]
fn is_off_unless_the_ssh_option_is_set() {
    run(|| async {
        let f = organization(|_| {}).await;
        let error = fails(
            f.iam
                .api
                .ssh
                .setup(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn sets_up_authorities_enrolls_hosts_and_hands_them_what_sshd_needs() {
    run(|| async {
        let t = setup().await;
        assert_eq!(t.setup["created"], json!(["user", "host"]));
        let kinds: Vec<(String, String)> = t.setup["authorities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (s(&a["kind"]), s(&a["status"])))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("user".to_owned(), "active".to_owned()),
                ("host".to_owned(), "active".to_owned())
            ]
        );
        // Setup is idempotent.
        let again = ok(t
            .f
            .iam
            .api
            .ssh
            .setup(t.owner(), body(json!({ "tenantId": t.tenant() })))
            .await);
        assert_eq!(again["created"], json!([]));
        // Authority keys are sealed at rest and never leave in views.
        let stored =
            t.f.find(
                "sshAuthorities",
                Filter::new().eq("tenantId", t.tenant().to_owned()),
            )
            .await;
        assert!(stored.iter().all(|row| {
            row["keySealed"]
                .as_str()
                .is_some_and(|sealed| !sealed.contains("MC4C"))
        }));
        assert!(!t.setup.to_string().contains("keySealed"));

        let cert = parse_certificate(&s(&t.web_setup["certificate"]));
        assert_eq!(cert.kind, 2);
        assert_eq!(cert.key_id, "host:web-01");
        assert_eq!(
            cert.principals,
            vec!["web-01", "web-01.acme.test", "10.0.0.5"]
        );
        assert_eq!(
            cert.public_key_fingerprint,
            line_fingerprint(&t.web_host_key)
        );
        assert!(cert.signature_valid);
        let host_authority = t.setup["authorities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["kind"] == json!("host"))
            .unwrap();
        assert_eq!(
            cert.signature_key_fingerprint,
            s(&host_authority["fingerprint"])
        );
        assert_eq!(
            t.web_setup["principals"],
            json!({ "deploy": "deploy@web-01\n", "root": "root@web-01\n" })
        );
        let user_key = s(&t.setup["authorities"][0]["publicKey"]);
        assert!(s(&t.web_setup["trustedUserCaKeys"]).contains(user_key.split(' ').nth(1).unwrap()));
        let sshd = s(&t.web_setup["sshdConfig"]);
        assert!(sshd.contains("AuthorizedPrincipalsFile /etc/ssh/better-iam/principals/%u"));
        assert!(sshd.contains("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"));
        let paths: Vec<String> = t.web_setup["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| s(&file["path"]))
            .collect();
        assert!(paths.contains(&"/etc/ssh/better-iam/revoked.krl".to_owned()));
        assert!(paths.contains(&"/etc/ssh/sshd_config.d/00-better-iam.conf".to_owned()));
        assert_eq!(
            t.web_setup["managedDirectories"],
            json!(["/etc/ssh/better-iam/principals"])
        );
        assert!(s(&t.web_setup["renewalToken"]).starts_with("biam_sshr."));
        assert!(t.web_setup["host"].get("renewalTokenHash").is_none());

        // The join token works once.
        let again =
            t.f.iam
                .api
                .ssh
                .enroll_host(body(
                    json!({ "joinToken": t.web["joinToken"], "publicKey": t.web_host_key }),
                ))
                .await;
        assert_eq!(fails(again).code, "INVALID_TOKEN");
        // Syncing with the renewal token reuses a fresh certificate and hands out the same setup.
        let synced = sync(&t, json!({ "renewalToken": t.web_setup["renewalToken"] }))
            .await
            .unwrap();
        assert_eq!(synced["certificateRenewed"], json!(false));
        assert_eq!(synced["certificate"], t.web_setup["certificate"]);
        assert!(synced.get("renewalToken").is_none());
        let bad = format!("{}x", s(&t.web_setup["renewalToken"]));
        assert_eq!(
            error_code(sync(&t, json!({ "renewalToken": bad })).await),
            "INVALID_TOKEN"
        );

        // Members' clients trust the host authority for exactly the enrolled names; the public trust lists none.
        let client = ok(t
            .f
            .iam
            .api
            .ssh
            .client_trust(t.owner(), body(json!({ "tenantId": t.tenant() })))
            .await);
        let known = s(&client["knownHosts"]);
        assert!(
            known
                .starts_with("@cert-authority 10.0.0.5,db-01,web-01,web-01.acme.test ssh-ed25519 ")
        );
        assert!(known.contains(" better-iam:"));
        let trust = ok(t
            .f
            .iam
            .api
            .ssh
            .trust(body(json!({ "tenantId": t.tenant() })))
            .await);
        assert_eq!(trust["userAuthorities"].as_array().unwrap().len(), 1);
        assert_eq!(trust["knownHosts"], json!(""));
        assert!(!trust.to_string().contains("web-01"));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn issues_certificates_for_exactly_the_hosts_and_logins_policies_allow() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let public_key = ssh_public_key("ed25519", "alice@laptop");
        let access = ok(ssh
            .my_access(&t.alice_session, body(json!({ "tenantId": t.tenant() })))
            .await);
        assert_eq!(
            access["hosts"],
            json!([{
                "name": "web-01",
                "addresses": ["web-01.acme.test", "10.0.0.5"],
                "labels": { "environment": "staging" },
                "logins": ["deploy"],
                "forwarding": { "port": true, "agent": false, "x11": false },
            }])
        );

        let issued = issue(
            &t,
            &t.alice_session,
            json!({ "publicKey": public_key, "ttlMs": HOUR, "reason": "deploy release 42" }),
        )
        .await
        .unwrap();
        assert_eq!(issued["principals"], json!(["deploy@web-01"]));
        assert_eq!(
            issued["hosts"],
            json!([{ "name": "web-01", "addresses": ["web-01.acme.test", "10.0.0.5"], "logins": ["deploy"] }])
        );
        assert_eq!(issued["validBefore"].as_f64().unwrap() - t.f.now(), HOUR);
        let cert = parse_certificate(&s(&issued["certificate"]));
        assert_eq!(cert.kind, 1);
        assert_eq!(cert.principals, vec!["deploy@web-01"]);
        assert_eq!(cert.public_key_fingerprint, line_fingerprint(&public_key));
        assert_eq!(
            cert.extensions,
            vec!["permit-port-forwarding", "permit-pty", "permit-user-rc"]
        );
        assert!(cert.signature_valid);
        assert_eq!(cert.key_id, format!("alice@acme.test ({})", t.alice));
        assert_eq!(
            cert.valid_before,
            (issued["validBefore"].as_f64().unwrap() / 1000.0).floor() as u64
        );
        assert!(s(&issued["knownHosts"]).contains("@cert-authority"));
        let krl = STANDARD.decode(s(&issued["revokedHostKeys"])).unwrap();
        assert_eq!(&krl[..6], b"SSHKRL");

        // Asking for a host or login outside the grant is refused and audited.
        for (input, expected) in [
            (
                json!({ "publicKey": public_key, "hosts": ["db-01"] }),
                "ACCESS_DENIED",
            ),
            (
                json!({ "publicKey": public_key, "logins": ["root"] }),
                "ACCESS_DENIED",
            ),
            (
                json!({ "publicKey": public_key, "hosts": ["nope"] }),
                "NOT_FOUND",
            ),
        ] {
            assert_eq!(
                error_code(issue(&t, &t.alice_session, input).await),
                expected
            );
        }
        let events = audit_of(&t.f).await;
        assert!(has_event(&events, "ssh:login", "deny", |_| true));
        assert!(has_event(
            &events,
            "ssh:certificate:issue",
            "allow",
            |event| { event["metadata"]["reason"] == json!("deploy release 42") }
        ));

        // The owner (every grant) gets every login on every host; lifetimes are capped by the tenant maximum.
        let owner = issue(
            &t,
            t.owner(),
            json!({ "publicKey": key("rsa"), "ttlMs": 20.0 * HOUR }),
        )
        .await
        .unwrap();
        assert_eq!(
            owner["principals"],
            json!([
                "postgres@db-01",
                "root@db-01",
                "deploy@web-01",
                "root@web-01"
            ])
        );
        assert_eq!(
            owner["validBefore"].as_f64().unwrap() - t.f.now(),
            16.0 * HOUR
        );
        assert_eq!(
            owner["extensions"],
            json!([
                "permit-X11-forwarding",
                "permit-agent-forwarding",
                "permit-port-forwarding",
                "permit-pty",
                "permit-user-rc",
            ])
        );

        // The generic decision API and access reviews see the same resources.
        let decision =
            t.f.iam
                .authorize(&AuthorizationRequest {
                    credential: t.alice_session.clone(),
                    tenant_id: t.tenant().to_owned(),
                    action: "ssh:login".into(),
                    resource: ResourceTarget {
                        kind: "ssh-login".into(),
                        id: "web-01/deploy".into(),
                    },
                })
                .await
                .unwrap();
        assert!(decision.allowed);
        let hosts = ok(ssh
            .list_hosts(t.owner(), body(json!({ "tenantId": t.tenant() })))
            .await);
        let web = hosts
            .as_array()
            .unwrap()
            .iter()
            .find(|host| host["name"] == json!("web-01"))
            .unwrap()
            .clone();
        let who = ok(ssh
            .who_can_login(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "hostId": web["id"] })),
            )
            .await);
        let entries: Vec<(Value, Value)> = who["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| (entry["email"].clone(), entry["logins"].clone()))
            .collect();
        assert!(entries.contains(&(json!("alice@acme.test"), json!(["deploy"]))));
        assert!(entries.contains(&(json!("owner@acme.test"), json!(["deploy", "root"]))));

        let mine = ok(ssh
            .my_certificates(&t.alice_session, body(json!({ "tenantId": t.tenant() })))
            .await);
        let mine = mine.as_array().unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(
            (&mine[0]["id"], &mine[0]["status"]),
            (&issued["id"], &json!("active"))
        );
        assert!(mine[0].get("sessionId").is_none());
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn enforces_tenant_settings_mfa_security_keys_source_address_lifetimes() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let settings = |input: Value| {
            let mut request = json!({ "tenantId": t.tenant() });
            for (key, value) in input.as_object().cloned().unwrap_or_default() {
                request[key] = value;
            }
            body(request)
        };
        ok(ssh
            .update_settings(t.owner(), settings(json!({ "requireMfa": true })))
            .await);
        assert_eq!(
            error_code(issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") })).await),
            "MFA_REQUIRED"
        );
        ok(ssh
            .update_settings(
                t.owner(),
                settings(json!({
                    "requireMfa": false,
                    "requireSecurityKey": true,
                    "requireUserVerification": true,
                    "defaultCertificateMs": 600_000,
                })),
            )
            .await);
        assert_eq!(
            error_code(issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") })).await),
            "SECURITY_KEY_REQUIRED"
        );
        let sk = issue(
            &t,
            &t.alice_session,
            json!({ "publicKey": key("sk-ed25519") }),
        )
        .await
        .unwrap();
        assert_eq!(sk["validBefore"].as_f64().unwrap() - t.f.now(), 600_000.0);
        let parsed = parse_certificate(&s(&sk["certificate"]));
        assert_eq!(parsed.kind_name, "sk-ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(
            parsed.critical_options,
            vec![("verify-required".to_owned(), String::new())]
        );

        ok(ssh
            .update_settings(
                t.owner(),
                settings(json!({ "requireSecurityKey": false, "bindSourceAddress": true })),
            )
            .await);
        // No client address is known in-process: refused rather than issued unbound.
        assert_eq!(
            error_code(issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") })).await),
            "SOURCE_ADDRESS_UNKNOWN"
        );
        let error = fails(
            ssh.update_settings(
                t.owner(),
                settings(json!({ "defaultCertificateMs": 20.0 * HOUR })),
            )
            .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        let error = fails(
            ssh.update_settings(
                t.owner(),
                settings(json!({ "hostPatterns": ["bad pattern"] })),
            )
            .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        // Members without iam:ssh:manage cannot change settings or enroll hosts.
        let error = fails(
            ssh.update_settings(&t.alice_session, settings(json!({ "requireMfa": false })))
                .await,
        );
        assert_eq!(error.code, "ACCESS_DENIED");
        let error = fails(
            ssh.create_host(
                &t.alice_session,
                body(json!({ "tenantId": t.tenant(), "name": "x", "logins": ["a"] })),
            )
            .await,
        );
        assert_eq!(error.code, "ACCESS_DENIED");
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn revokes_certificates_and_publishes_them_in_the_revocation_lists() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let public_key = key("ed25519");
        let first = issue(&t, &t.alice_session, json!({ "publicKey": public_key }))
            .await
            .unwrap();
        let second = issue(&t, &t.alice_session, json!({ "publicKey": public_key }))
            .await
            .unwrap();
        let empty = revocation(&t, json!({})).await;
        assert_eq!(empty["revokedCertificates"], json!(0));

        // A person may revoke their own certificate without any permission.
        let revoked = ok(ssh
            .revoke_certificate(
                &t.alice_session,
                body(json!({ "tenantId": t.tenant(), "certificateId": first["id"] })),
            )
            .await);
        assert_eq!(revoked["status"], json!("revoked"));
        assert_eq!(revoked["revocationReason"], json!("revoked"));
        assert_eq!(revoked["revokedBy"], json!(t.alice));
        // Cached lists are keyed by version, so the new one shows at once.
        let list = revocation(&t, json!({})).await;
        assert_eq!(list["revokedCertificates"], json!(1));
        assert_eq!(
            list["version"].as_f64().unwrap(),
            empty["version"].as_f64().unwrap() + 1.0
        );

        // Disabling the database host revokes its certificate and publishes its key to clients (never in the user
        // list).
        ok(ssh
            .disable_host(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "hostId": t.db["host"]["id"] })),
            )
            .await);
        let users = revocation(&t, json!({})).await;
        assert_eq!(
            (
                &users["kind"],
                &users["revokedCertificates"],
                &users["revokedHostKeys"]
            ),
            (&json!("user"), &json!(1), &json!(0))
        );
        let hosts = revocation(&t, json!({ "kind": "host" })).await;
        assert_eq!(
            (
                &hosts["kind"],
                &hosts["revokedCertificates"],
                &hosts["revokedHostKeys"]
            ),
            (&json!("host"), &json!(1), &json!(1))
        );
        let client = ok(ssh
            .client_trust(&t.alice_session, body(json!({ "tenantId": t.tenant() })))
            .await);
        let known = s(&client["knownHosts"]);
        assert!(known.contains("@revoked * ecdsa-sha2-nistp256 "));
        assert!(known.contains(" better-iam:revoked"));
        assert_eq!(
            error_code(sync(&t, json!({ "renewalToken": t.db_setup["renewalToken"] })).await),
            "INVALID_TOKEN"
        );

        if let Some(keygen) = ssh_keygen() {
            let folder = tempfile::tempdir().unwrap();
            let path = |name: &str| folder.path().join(name).to_string_lossy().into_owned();
            std::fs::write(
                path("first-cert.pub"),
                format!("{}\n", s(&first["certificate"])),
            )
            .unwrap();
            std::fs::write(
                path("second-cert.pub"),
                format!("{}\n", s(&second["certificate"])),
            )
            .unwrap();
            std::fs::write(
                path("revoked.krl"),
                STANDARD.decode(s(&users["krl"])).unwrap(),
            )
            .unwrap();
            let (_, output) = run_keygen(
                &keygen,
                &["-Q", "-f", &path("revoked.krl"), &path("first-cert.pub")],
            );
            assert!(output.contains("REVOKED"), "{output}");
            let (status, output) = run_keygen(
                &keygen,
                &["-Q", "-f", &path("revoked.krl"), &path("second-cert.pub")],
            );
            assert_eq!(status, 0, "{output}");
        }

        // Incident response: everything alice holds, at once.
        let revoked = ok(ssh
            .revoke_identity(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "identityId": t.alice })),
            )
            .await);
        assert_eq!(revoked, json!({ "revoked": 1 }));
        // Someone else's certificate needs iam:ssh:manage.
        let owners = issue(&t, t.owner(), json!({ "publicKey": public_key }))
            .await
            .unwrap();
        let error = fails(
            ssh.revoke_certificate(
                &t.alice_session,
                body(json!({ "tenantId": t.tenant(), "certificateId": owners["id"] })),
            )
            .await,
        );
        assert_eq!(error.code, "ACCESS_DENIED");
        let all = ok(ssh
            .list_certificates(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "user", "status": "revoked" })),
            )
            .await);
        assert_eq!(all["total"], json!(2));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn ends_certificates_with_the_session_or_api_key_that_requested_them() {
    run(|| async {
        let t = setup().await;
        let api = &t.f.iam.api;
        let cert = issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        ok(api
            .identities
            .revoke_sessions(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "identityId": t.alice })),
            )
            .await);
        // Hosts refuse it from their next revocation list, before the sweep even runs.
        assert_eq!(
            revocation(&t, json!({})).await["revokedCertificates"],
            json!(1)
        );

        let robot = ok(api
            .service_accounts
            .create(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "name": "deployer" })),
            )
            .await);
        bind(&t.f, &t.role, &s(&robot["id"]), json!({})).await;
        let api_key = ok(api
            .credentials
            .create(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "identityId": robot["id"] })),
            )
            .await);
        let robot_cert = issue(
            &t,
            &bearer(&s(&api_key["token"])),
            json!({ "publicKey": key("ed25519") }),
        )
        .await
        .unwrap();
        assert_eq!(robot_cert["principals"], json!(["deploy@web-01"]));
        ok(api
            .credentials
            .revoke(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "credentialId": api_key["credentialId"] })),
            )
            .await);

        let swept =
            t.f.iam
                .ssh
                .sweep(Some(&json!({ "tenantId": t.tenant() })))
                .await
                .unwrap();
        assert_eq!(
            serde_json::to_value(&swept).unwrap(),
            json!({ "examined": 2, "revoked": 2, "byReason": { "session-ended": 2 } })
        );
        let records = ok(api
            .ssh
            .list_certificates(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "user" })),
            )
            .await);
        let mut ids: Vec<String> = records["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| s(&c["id"]))
            .collect();
        ids.sort();
        let mut expected = vec![s(&cert["id"]), s(&robot_cert["id"])];
        expected.sort();
        assert_eq!(ids, expected);
        assert!(
            records["certificates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["revocationReason"] == json!("session-ended"))
        );
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn sweeps_certificates_whose_holder_login_or_access_went_away() {
    run(|| async {
        let t = setup().await;
        let api = &t.f.iam.api;
        let bob = t.f.member("bob").await;
        let carol = t.f.member("carol").await;
        for person in [&bob, &carol] {
            bind(&t.f, &t.role, person, json!({})).await;
        }
        let bob_session = t.f.sign_in(&bob).await;
        let carol_session = t.f.sign_in(&carol).await;
        let alice_cert = issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        let bob_cert = issue(&t, &bob_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        let swept = t.f.iam.ssh.sweep(None).await.unwrap();
        assert_eq!(
            serde_json::to_value(&swept).unwrap(),
            json!({ "examined": 2, "revoked": 0, "byReason": {} })
        );

        // Alice's account is disabled: the revocation list refuses her certificate even before the sweep runs.
        ok(api
            .identities
            .set_status(
                t.owner(),
                body(
                    json!({ "tenantId": t.tenant(), "identityId": t.alice, "status": "disabled" }),
                ),
            )
            .await);
        assert_eq!(
            revocation(&t, json!({})).await["revokedCertificates"],
            json!(1)
        );
        // Bob loses the grant: his certificate no longer matches policy.
        let bindings = ok(api
            .bindings
            .list(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "subjectId": bob })),
            )
            .await);
        let list = match &bindings {
            Value::Array(items) => items.clone(),
            other => other["bindings"].as_array().cloned().unwrap_or_default(),
        };
        let binding = list
            .iter()
            .find(|item| item["roleId"] == json!(t.role))
            .unwrap()
            .clone();
        ok(api
            .bindings
            .delete(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "bindingId": binding["id"] })),
            )
            .await);

        let swept =
            t.f.iam
                .ssh
                .sweep(Some(&json!({ "tenantId": t.tenant() })))
                .await
                .unwrap();
        assert_eq!(
            serde_json::to_value(&swept).unwrap(),
            json!({ "examined": 2, "revoked": 2, "byReason": { "identity-inactive": 1, "access-changed": 1 } })
        );
        let records = ok(api
            .ssh
            .list_certificates(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "user" })),
            )
            .await);
        let reasons: HashMap<String, Value> = records["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (s(&c["id"]), c["revocationReason"].clone()))
            .collect();
        assert_eq!(
            reasons,
            HashMap::from([
                (s(&alice_cert["id"]), json!("identity-inactive")),
                (s(&bob_cert["id"]), json!("access-changed")),
            ])
        );
        let krl = t.f.iam.ssh.revocation_list(t.tenant(), None).await.unwrap();
        let bytes = STANDARD.decode(s(&krl["bytes"]["$bytes"])).unwrap();
        assert_eq!(&bytes[..8], b"SSHKRL\n\0");

        // A login removed from the host takes the certificates naming it (the host deletes its principals file
        // too).
        let carol_cert = issue(&t, &carol_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        ok(api
            .ssh
            .update_host(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "hostId": t.web["host"]["id"], "logins": ["root"] })),
            )
            .await);
        let swept =
            t.f.iam
                .ssh
                .sweep(Some(&json!({ "tenantId": t.tenant() })))
                .await
                .unwrap();
        assert_eq!(swept.by_reason, json!({ "access-changed": 1 }));
        let carol_record = ok(api
            .ssh
            .get_certificate(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "certificateId": carol_cert["id"] })),
            )
            .await);
        assert_eq!(carol_record["status"], json!("revoked"));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn caps_certificates_at_the_time_limited_grants_that_allow_them() {
    run(|| async {
        let t = setup().await;
        let dave = t.f.member("dave").await;
        let role = create_role(
            &t.f,
            "Database on call",
            json!([{ "effect": "allow", "actions": ["ssh:login"], "resources": ["ssh-login/db-01/postgres"] }]),
        )
        .await;
        bind(
            &t.f,
            &role,
            &dave,
            json!({ "expiresAt": t.f.now() + 2.0 * HOUR }),
        )
        .await;
        let dave_session = t.f.sign_in(&dave).await;
        let cert = issue(&t, &dave_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        assert_eq!(cert["principals"], json!(["postgres@db-01"]));
        assert_eq!(
            cert["validBefore"].as_f64().unwrap(),
            t.f.now() + 2.0 * HOUR
        );
        // A standing grant sets no such limit.
        let standing = issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        assert_eq!(
            standing["validBefore"].as_f64().unwrap() - t.f.now(),
            8.0 * HOUR
        );
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn keeps_the_host_authority_to_names_the_organization_owns_unique_per_host() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let patterns =
            |patterns: Value| body(json!({ "tenantId": t.tenant(), "hostPatterns": patterns }));
        // `*` and names outside the verified domains are refused as patterns; patterns must cover every host.
        for value in [
            json!(["*"]),
            json!(["*.github.com"]),
            json!(["*m"]),
            json!(["*.acme.test"]),
        ] {
            let error = fails(ssh.update_settings(t.owner(), patterns(value)).await);
            assert_eq!(error.code, "HOST_OUTSIDE_PATTERNS");
        }
        ok(ssh
            .update_settings(
                t.owner(),
                patterns(json!([
                    "*.acme.test",
                    "web-*",
                    "db-*",
                    "10.0.0.*",
                    "!bastion.acme.test"
                ])),
            )
            .await);
        // A name outside them (github.com, a negated name) can never enter a host certificate.
        for input in [
            json!({ "name": "web-02", "addresses": ["github.com"], "logins": ["deploy"] }),
            json!({ "name": "bastion.acme.test", "logins": ["ops"] }),
        ] {
            let mut request = input.clone();
            request["tenantId"] = json!(t.tenant());
            let error = fails(ssh.create_host(t.owner(), body(request)).await);
            assert_eq!(error.code, "HOST_OUTSIDE_PATTERNS");
        }
        let error = fails(
            ssh.update_host(
                t.owner(),
                body(json!({
                    "tenantId": t.tenant(),
                    "hostId": t.web["host"]["id"],
                    "addresses": ["evil.example.com"],
                })),
            )
            .await,
        );
        assert_eq!(error.code, "HOST_OUTSIDE_PATTERNS");
        // Another host's names are taken.
        let error = fails(
            ssh.create_host(
                t.owner(),
                body(json!({
                    "tenantId": t.tenant(),
                    "name": "web-02",
                    "addresses": ["web-01.acme.test"],
                    "logins": ["deploy"],
                })),
            )
            .await,
        );
        assert_eq!(error.code, "HOST_NAME_TAKEN");
        let trust = ok(ssh.trust(body(json!({ "tenantId": t.tenant() }))).await);
        assert!(
            s(&trust["knownHosts"])
                .starts_with("@cert-authority *.acme.test,web-*,db-*,10.0.0.*,!bastion.acme.test ")
        );
        // An authority key or another host's key is never accepted as a host key.
        let spare = ok(ssh
            .create_host(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "name": "web-03", "logins": ["deploy"] })),
            )
            .await);
        let error = fails(
            ssh.enroll_host(body(json!({
                "joinToken": spare["joinToken"],
                "publicKey": t.setup["authorities"][0]["publicKey"],
            })))
            .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        let error = fails(
            ssh.enroll_host(body(json!({
                "joinToken": spare["joinToken"],
                "publicKey": t.web_setup["host"]["hostKey"],
            })))
            .await,
        );
        assert_eq!(error.code, "HOST_KEY_IN_USE");
        let events = audit_of(&t.f).await;
        let reasons: Vec<Value> = events
            .iter()
            .filter(|event| {
                event["action"] == json!("iam:ssh:manage") && event["outcome"] == json!("deny")
            })
            .map(|event| event["metadata"]["reason"].clone())
            .collect();
        assert!(reasons.contains(&json!("HOST_OUTSIDE_PATTERNS")));
        assert!(reasons.contains(&json!("HOST_NAME_TAKEN")));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn scopes_host_administration_to_the_names_an_administrator_manages() {
    run(|| async {
        let t = setup().await;
        let bob = t.f.member("bob").await;
        let role = create_role(
            &t.f,
            "Team A hosts",
            json!([{ "effect": "allow", "actions": ["iam:ssh:manage"], "resources": ["iam/ssh/hosts/team-a-*"] }]),
        )
        .await;
        bind(&t.f, &role, &bob, json!({})).await;
        let bob_session = t.f.sign_in(&bob).await;
        let create = |addresses: Value| {
            t.f.iam.api.ssh.create_host(
                &bob_session,
                body(json!({
                    "tenantId": t.tenant(),
                    "name": "team-a-box",
                    "addresses": addresses,
                    "logins": ["deploy"],
                })),
            )
        };
        assert_eq!(
            fails(create(json!(["web-01.acme.test"])).await).code,
            "HOST_NAME_TAKEN"
        );
        assert_eq!(
            fails(create(json!(["payroll.acme.test"])).await).code,
            "ACCESS_DENIED"
        );
        let created = ok(create(json!(["team-a-box.acme.test"])).await);
        assert_eq!(
            created["host"]["addresses"],
            json!(["team-a-box.acme.test"])
        );
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn rebuilds_hosts_supersedes_old_certificates_rotates_renewal_tokens_refuses_key_swaps() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let token = t.web_setup["renewalToken"].clone();
        // A renewal token cannot move the host to another key; the attempt is audited.
        assert_eq!(
            error_code(
                sync(
                    &t,
                    json!({ "renewalToken": token, "publicKey": key("ed25519") })
                )
                .await
            ),
            "HOST_KEY_CHANGED"
        );
        assert!(has_event(
            &audit_of(&t.f).await,
            "ssh:host:sync",
            "deny",
            |event| { event["metadata"]["reason"] == json!("HOST_KEY_CHANGED") }
        ));
        // A forced renewal is honoured at most hourly, and rotates the renewal token (the old one works until the
        // new is used).
        let early = sync(&t, json!({ "renewalToken": token, "renew": true }))
            .await
            .unwrap();
        assert_eq!(early["certificateRenewed"], json!(false));
        t.f.advance(2.0 * HOUR);
        let renewed = sync(&t, json!({ "renewalToken": token, "renew": true }))
            .await
            .unwrap();
        assert_eq!(renewed["certificateRenewed"], json!(true));
        assert!(s(&renewed["renewalToken"]).starts_with("biam_sshr."));
        let old = sync(&t, json!({ "renewalToken": token })).await.unwrap();
        assert_eq!(old["certificateRenewed"], json!(false));
        sync(&t, json!({ "renewalToken": renewed["renewalToken"] }))
            .await
            .unwrap();
        assert_eq!(
            error_code(sync(&t, json!({ "renewalToken": token })).await),
            "INVALID_TOKEN"
        );
        // Re-enrolling a rebuilt host takes a fresh join token; every earlier certificate is superseded and the old
        // key is published to clients as revoked.
        let reset = ok(ssh
            .reset_join_token(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "hostId": t.web["host"]["id"] })),
            )
            .await);
        let rebuilt = ok(ssh
            .enroll_host(body(
                json!({ "joinToken": reset["joinToken"], "publicKey": key("ed25519") }),
            ))
            .await);
        assert_eq!(
            error_code(sync(&t, json!({ "renewalToken": renewed["renewalToken"] })).await),
            "INVALID_TOKEN"
        );
        let fresh = sync(&t, json!({ "renewalToken": rebuilt["renewalToken"] }))
            .await
            .unwrap();
        assert_eq!(fresh["certificateRenewed"], json!(false));
        let host_certs = ok(ssh
            .list_certificates(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "host", "hostId": t.web["host"]["id"] })),
            )
            .await);
        let certificates = host_certs["certificates"].as_array().unwrap();
        assert_eq!(
            certificates
                .iter()
                .filter(|c| c["status"] == json!("active"))
                .count(),
            1
        );
        let reasons: Vec<Value> = certificates
            .iter()
            .filter(|c| c["status"] == json!("revoked"))
            .map(|c| c["revocationReason"].clone())
            .collect();
        assert_eq!(reasons, vec![json!("superseded"), json!("superseded")]);
        let client = ok(ssh
            .client_trust(t.owner(), body(json!({ "tenantId": t.tenant() })))
            .await);
        let known = s(&client["knownHosts"]);
        let old_key: Vec<&str> = t.web_setup["host"]["hostKey"]
            .as_str()
            .unwrap()
            .split(' ')
            .take(2)
            .collect();
        assert!(known.contains(&format!("@revoked * {}", old_key.join(" "))));
        let new_key = s(&rebuilt["host"]["hostKey"]);
        assert!(!known.contains(new_key.split(' ').nth(1).unwrap()));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn revokes_every_user_certificate_while_the_organization_is_suspended() {
    run(|| async {
        let t = setup().await;
        issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        ok(t.f
            .iam
            .api
            .tenants
            .set_status(
                &t.f.root_credential,
                body(json!({ "tenantId": t.tenant(), "status": "suspended" })),
            )
            .await);
        let list = revocation(&t, json!({})).await;
        assert_eq!(
            (&list["tenantActive"], &list["revokedCertificates"]),
            (&json!(false), &json!(1))
        );
        // Hosts still sync (and fetch that list), without new certificates.
        let synced = sync(
            &t,
            json!({ "renewalToken": t.web_setup["renewalToken"], "renew": true }),
        )
        .await
        .unwrap();
        assert_eq!(synced["certificateRenewed"], json!(false));
        assert_eq!(synced["revocationList"], list["krl"]);
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn rotates_authorities_without_breaking_certificates_already_issued() {
    run(|| async {
        let t = setup().await;
        let ssh = &t.f.iam.api.ssh;
        let before = issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        let pending = ok(ssh
            .rotate_authority(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "user" })),
            )
            .await);
        assert_eq!(pending["status"], json!("pending"));
        // Published ahead of signing: hosts trust both keys from their next sync.
        let synced = sync(&t, json!({ "renewalToken": t.web_setup["renewalToken"] }))
            .await
            .unwrap();
        assert_eq!(
            s(&synced["trustedUserCaKeys"]).trim().split('\n').count(),
            2
        );
        let error = fails(
            ssh.rotate_authority(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "kind": "user" })),
            )
            .await,
        );
        assert_eq!(error.code, "CONFLICT");
        ok(ssh
            .activate_authority(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "authorityId": pending["id"] })),
            )
            .await);
        let after = issue(&t, &t.alice_session, json!({ "publicKey": key("ed25519") }))
            .await
            .unwrap();
        assert_eq!(
            parse_certificate(&s(&after["certificate"])).signature_key_fingerprint,
            s(&pending["fingerprint"])
        );
        let old = t.setup["authorities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["kind"] == json!("user"))
            .unwrap()
            .clone();
        assert_eq!(
            parse_certificate(&s(&before["certificate"])).signature_key_fingerprint,
            s(&old["fingerprint"])
        );
        // The previous key stays trusted while its certificates live; retiring it early needs force.
        let error = fails(
            ssh.retire_authority(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "authorityId": old["id"] })),
            )
            .await,
        );
        assert_eq!(error.code, "RESOURCE_IN_USE");
        t.f.advance(17.0 * HOUR);
        let owner = t.f.session(&t.f.owner_id, false).await;
        let retired = ok(ssh
            .retire_authority(
                &owner,
                body(json!({ "tenantId": t.tenant(), "authorityId": old["id"] })),
            )
            .await);
        assert_eq!(retired["status"], json!("retired"));
        let trust = ok(ssh.trust(body(json!({ "tenantId": t.tenant() }))).await);
        let ids: Vec<Value> = trust["userAuthorities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["id"].clone())
            .collect();
        assert_eq!(ids, vec![pending["id"].clone()]);

        // A host rotation re-issues host certificates at the next sync.
        let host_pending = ok(ssh
            .rotate_authority(
                &owner,
                body(json!({ "tenantId": t.tenant(), "kind": "host", "activate": true })),
            )
            .await);
        let renewed = sync(&t, json!({ "renewalToken": t.web_setup["renewalToken"] }))
            .await
            .unwrap();
        assert_eq!(renewed["certificateRenewed"], json!(true));
        assert_eq!(
            parse_certificate(&s(&renewed["certificate"])).signature_key_fingerprint,
            s(&host_pending["fingerprint"])
        );
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn never_lets_the_platform_root_override_open_an_organization_host() {
    run(|| async {
        let t = setup().await;
        let root = t.f.root_credential.clone();
        assert_eq!(
            error_code(issue(&t, &root, json!({ "publicKey": key("ed25519") })).await),
            "ROOT_SSH_RESTRICTED"
        );
        let access = ok(t
            .f
            .iam
            .api
            .ssh
            .my_access(&root, body(json!({ "tenantId": t.tenant() })))
            .await);
        assert_eq!(access["hosts"], json!([]));
        // Root still administers the authority (audited as a root override).
        let status = ok(t
            .f
            .iam
            .api
            .ssh
            .status(&root, body(json!({ "tenantId": t.tenant() })))
            .await);
        assert_eq!(status["hosts"]["enrolled"], json!(2));
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn serves_hosts_over_http_without_a_session_and_members_with_a_bearer_token() {
    run(|| async {
        let t = setup().await;
        let host = ok(t
            .f
            .iam
            .api
            .ssh
            .create_host(
                t.owner(),
                body(json!({ "tenantId": t.tenant(), "name": "ci-runner", "logins": ["ci"] })),
            )
            .await);
        // A host enrolls with plain JSON (curl with the usual X-Better-IAM header), the join token its only
        // credential.
        let (status, enrolled) = post(
            &t.f,
            "enrollHost",
            json!({ "joinToken": host["joinToken"], "publicKey": key("ed25519") }),
            None,
        )
        .await;
        assert_eq!(status, 200);
        let setup_body = &enrolled["data"];
        assert!(s(&setup_body["certificate"]).starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let (status, _) = post(
            &t.f,
            "syncHost",
            json!({ "renewalToken": setup_body["renewalToken"] }),
            None,
        )
        .await;
        assert_eq!(status, 200);
        let (_, krl) = post(
            &t.f,
            "revocationList",
            json!({ "tenantId": t.tenant() }),
            None,
        )
        .await;
        assert!(s(&krl["data"]["krl"]).starts_with("U1NIS1JM"));
        // Members call issueCertificate with their credential; without one it is refused.
        let token = t.alice_session.token.clone().unwrap();
        let (status, issued) = post(
            &t.f,
            "issueCertificate",
            json!({ "tenantId": t.tenant(), "publicKey": key("ed25519"), "hosts": ["web-01"] }),
            Some(&token),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(issued["data"]["principals"], json!(["deploy@web-01"]));
        let (status, _) = post(
            &t.f,
            "issueCertificate",
            json!({ "tenantId": t.tenant(), "publicKey": key("ed25519") }),
            None,
        )
        .await;
        assert_eq!(status, 401);
        let (status, _) = post(
            &t.f,
            "syncHost",
            json!({ "renewalToken": "biam_sshr.x.y" }),
            None,
        )
        .await;
        assert_eq!(status, 401);
    });
}

#[test]
#[ignore = "needs ssh.ts and ssh-ca.ts (ssh unit)"]
fn produces_a_user_certificate_ssh_keygen_reads() {
    let Some(keygen) = ssh_keygen() else {
        return;
    };
    run(move || async move {
        let t = setup().await;
        let issued = issue(&t, &t.alice_session, json!({ "publicKey": key("ecdsa") }))
            .await
            .unwrap();
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("id-cert.pub");
        std::fs::write(&path, format!("{}\n", s(&issued["certificate"]))).unwrap();
        let (status, output) = run_keygen(&keygen, &["-L", "-f", &path.to_string_lossy()]);
        assert_eq!(status, 0, "{output}");
        assert!(output.contains("user certificate"));
        assert!(output.contains("deploy@web-01"));
        assert!(output.contains("permit-port-forwarding"));
        assert!(!output.contains("permit-agent-forwarding"));
    });
}
