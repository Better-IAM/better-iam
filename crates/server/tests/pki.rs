//! The private certificate authority: ported from tests/pki.test.ts and tests/pki-security.test.ts, plus the X.509
//! layer (x509.ts) on its own.
//!
//! Every TypeScript test creates its authorities through `pki.createAuthority`, whose signing keys are KMS keys
//! (`createServiceKey`, `kmsSignFor` of kms.ts). Until kms.ts is ported in Rust, those ports are marked `#[ignore]`
//! with that reason. The tests that run now cover the same behavior without KMS: the X.509 encoding, requests,
//! canonical names and CRLs directly, and verification, revocation, listing, updates and trust bundles on authorities
//! and certificates seeded exactly as `createAuthority` and `issueCertificate` store them (signed here with local
//! P-256 keys). The TypeScript tests also complete real mutual TLS handshakes with Node's `tls`; the Rust tests check
//! the same certificate members with the port of Node's `X509Certificate` (x509.rs) instead.

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter};
use better_iam_server::pki::certificate_pem;
use better_iam_server::x509::{
    CaSpec, CertListSpec, CertificateRequestInput, CertificateSpec, DistinguishedName,
    PermittedNames, PrivateKey, RevokedEntry, SubjectAltNames, X509Certificate,
    create_certificate_request, encode_name, key_identifier, parse_certificate_request,
    random_serial, sha256_fingerprint, signed_structure, subject_alt_names, tbs_cert_list,
    tbs_certificate,
};
use organization_fixture::{Org, assert_matches, bearer, body, code, fails, ok, organization, run};
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

fn p256_secret() -> p256::SecretKey {
    loop {
        if let Ok(key) = p256::SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
            return key;
        }
    }
}

fn p384_secret() -> p384::SecretKey {
    loop {
        let bytes: Vec<u8> = (0..48).map(|_| rand::random::<u8>()).collect();
        if let Ok(key) = p384::SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

fn key_pair(kind: &str) -> PrivateKey {
    match kind {
        "ed25519" => PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&rand::random())),
        "rsa" => PrivateKey::Rsa(
            rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa key"),
        ),
        "p384" => PrivateKey::P384(p384_secret()),
        _ => PrivateKey::P256(p256_secret()),
    }
}

fn strings(values: &[&str]) -> Option<Vec<String>> {
    Some(values.iter().map(|value| value.to_string()).collect())
}

/// `createCertificateRequest({ privateKey, subject?: { commonName }, dnsNames?, uris?, ipAddresses?, emails? })`.
fn csr(
    key: PrivateKey,
    common_name: Option<&str>,
    dns_names: &[&str],
    uris: &[&str],
    ip_addresses: &[&str],
) -> String {
    let mut input = CertificateRequestInput::new(key);
    input.subject = common_name.map(DistinguishedName::common);
    if !dns_names.is_empty() {
        input.dns_names = strings(dns_names);
    }
    if !uris.is_empty() {
        input.uris = strings(uris);
    }
    if !ip_addresses.is_empty() {
        input.ip_addresses = strings(ip_addresses);
    }
    create_certificate_request(&input).expect("certificate request")
}

fn sign(key: &p256::SecretKey, data: &[u8]) -> Vec<u8> {
    let signature: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from(key).sign(data);
    signature.to_der().as_bytes().to_vec()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------------------------------------------
// The X.509 layer

#[test]
fn certificate_requests_round_trip_for_every_key_kind() {
    for (kind, key_type) in [
        ("p256", "ecc-p256"),
        ("p384", "ecc-p384"),
        ("ed25519", "ed25519"),
        ("rsa", "rsa-2048"),
    ] {
        let pem = csr(
            key_pair(kind),
            Some("api.internal"),
            &["API.internal", "api.internal", "*.jobs.internal"],
            &["spiffe://acme.test/billing"],
            &["127.0.0.1", "::ffff:10.0.0.1", "2001:db8:0:0:0:0:0:1"],
        );
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
        let parsed = parse_certificate_request(Some(&json!(pem))).expect(kind);
        assert_eq!(parsed.key_type, key_type);
        assert_eq!(parsed.common_name.as_deref(), Some("api.internal"));
        assert_eq!(parsed.names.dns_names, ["api.internal", "*.jobs.internal"]);
        assert_eq!(parsed.names.uris, ["spiffe://acme.test/billing"]);
        assert_eq!(
            parsed.names.ip_addresses,
            ["127.0.0.1", "10.0.0.1", "2001:db8::1"]
        );
    }
    // A request without names or subject still proves its key.
    let parsed =
        parse_certificate_request(Some(&json!(csr(key_pair("p256"), None, &[], &[], &[]))))
            .unwrap();
    assert_eq!(parsed.common_name, None);
    assert_eq!(parsed.names, SubjectAltNames::default());
    // PKCS#8 PEM keys are read too.
    let secret = p256_secret();
    let der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(der.as_bytes())
    );
    let key = PrivateKey::from_pkcs8_pem(&pem).unwrap();
    assert_eq!(
        key.spki().unwrap(),
        PrivateKey::P256(secret).spki().unwrap()
    );
}

#[test]
fn refuses_requests_whose_signature_does_not_prove_the_key() {
    let good = csr(key_pair("p256"), None, &["a.internal"], &[], &[]);
    let body: String = good
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut der = better_iam_server::x509::node_base64(&body);
    let at = der.len() - 5;
    der[at] ^= 0xff;
    let tampered = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        b64(&der)
    );
    let error = parse_certificate_request(Some(&json!(tampered))).unwrap_err();
    assert_eq!(code(&error), "INVALID_CSR");
    assert_eq!(
        error.message,
        "The request signature does not verify with its key"
    );
    // `not a csr` is base64 once its spaces are gone, so it fails as DER.
    let error = parse_certificate_request(Some(&json!("not a csr"))).unwrap_err();
    assert_eq!(
        (code(&error), error.message.as_str(), error.status),
        (
            "INVALID_CSR",
            "The certificate request is not valid DER",
            400
        )
    );
    let error = parse_certificate_request(Some(&json!("not-a-csr"))).unwrap_err();
    assert_eq!(error.message, "csr must be a PEM certificate request");
    let error = parse_certificate_request(Some(&json!(42))).unwrap_err();
    assert_eq!(code(&error), "INVALID_CSR");
    // Valid base64 that is not DER.
    let error = parse_certificate_request(Some(&json!("AAAA"))).unwrap_err();
    assert_eq!(error.message, "The certificate request is not valid DER");
}

#[test]
fn decides_and_encodes_the_same_canonical_names() {
    let names = |value: Value| subject_alt_names(&value);
    // Non-ASCII email local parts would be truncated to other bytes when encoded.
    assert_eq!(
        names(json!({ "emails": ["ţeo@corp.internal"] }))
            .unwrap_err()
            .message,
        "Invalid email address ţeo@corp.internal"
    );
    // Dot segments and non-canonical forms in URIs are refused rather than normalized behind the policy's back.
    assert!(
        names(json!({ "uris": ["spiffe://acme.test/team-a/../service/x"] }))
            .unwrap_err()
            .message
            .starts_with("Invalid SPIFFE ID")
    );
    assert_eq!(
        names(json!({ "uris": ["https://Acme.test/x"] }))
            .unwrap_err()
            .message,
        "Invalid URI https://Acme.test/x"
    );
    assert!(names(json!({ "uris": ["https://user@acme.test/x"] })).is_err());
    assert!(names(json!({ "uris": ["https://acme.test:443/x"] })).is_err());
    assert!(names(json!({ "uris": ["https://acme.test/x"] })).is_ok());
    // IP addresses are canonical: an IPv4-mapped IPv6 address is the IPv4 address.
    assert_eq!(
        names(json!({ "ipAddresses": ["::ffff:10.0.0.1", "2001:DB8::0:1", "fe80::1%eth0"] }))
            .unwrap_err()
            .message,
        "Invalid IP address fe80::1%eth0"
    );
    let canonical = names(json!({ "ipAddresses": ["::ffff:10.0.0.1", "2001:DB8::0:1"] })).unwrap();
    assert_eq!(canonical.ip_addresses, ["10.0.0.1", "2001:db8::1"]);
    assert!(names(json!({ "ipAddresses": ["01.2.3.4"] })).is_err());
    assert_eq!(
        names(json!({ "dnsNames": "a.internal" }))
            .unwrap_err()
            .message,
        "dnsNames must be a list of strings"
    );
    assert_eq!(
        names(json!({ "dnsNames": ["bad_name.internal"] }))
            .unwrap_err()
            .message,
        "Invalid DNS name bad_name.internal"
    );
    let many: Vec<String> = (0..101).map(|index| format!("h{index}.internal")).collect();
    assert_eq!(
        names(json!({ "dnsNames": many })).unwrap_err().message,
        "At most 100 subject alternative names"
    );
}

/// A self-signed P-256 root, an intermediate below it, and leaves, encoded as the authority encodes them.
struct Chain {
    root_key: p256::SecretKey,
    root_subject: Vec<u8>,
    root_key_id: Vec<u8>,
    root: Vec<u8>,
    issuing_key: p256::SecretKey,
    issuing_subject: Vec<u8>,
    issuing_key_id: Vec<u8>,
    issuing: Vec<u8>,
}

fn chain(now: f64) -> Chain {
    let root_key = p256_secret();
    let root_spki = PrivateKey::P256(root_key.clone()).spki().unwrap();
    let root_name = DistinguishedName {
        common_name: Some("Acme Root CA".into()),
        organization: Some("Acme".into()),
        country: Some("US".into()),
        ..DistinguishedName::default()
    };
    let root_subject = encode_name(&root_name);
    let root_key_id = key_identifier(&root_spki).unwrap();
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: random_serial(),
            issuer: root_subject.clone(),
            subject: root_name,
            spki: root_spki,
            not_before: now - 60_000.0,
            not_after: now + 3650.0 * DAY,
            ca: Some(CaSpec {
                path_length: Some(1.0),
            }),
            ..CertificateSpec::default()
        },
        "ES256",
    )
    .unwrap();
    let root = signed_structure(&tbs, "ES256", &sign(&root_key, &tbs));
    let issuing_key = p256_secret();
    let issuing_spki = PrivateKey::P256(issuing_key.clone()).spki().unwrap();
    let issuing_name = DistinguishedName {
        common_name: Some("Acme Workload CA".into()),
        organization: Some("Acme".into()),
        ..DistinguishedName::default()
    };
    let issuing_subject = encode_name(&issuing_name);
    let issuing_key_id = key_identifier(&issuing_spki).unwrap();
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: random_serial(),
            issuer: root_subject.clone(),
            subject: issuing_name,
            spki: issuing_spki,
            not_before: now - 60_000.0,
            not_after: now + 1825.0 * DAY,
            ca: Some(CaSpec {
                path_length: Some(0.0),
            }),
            authority_key_id: Some(root_key_id.clone()),
            crl_url: Some("https://pki.acme.test/crl/workloads.crl".into()),
            permitted: Some(PermittedNames {
                dns_names: strings(&["internal", "localhost"]),
                uri_hosts: strings(&["acme.test"]),
            }),
            ..CertificateSpec::default()
        },
        "ES256",
    )
    .unwrap();
    let issuing = signed_structure(&tbs, "ES256", &sign(&root_key, &tbs));
    Chain {
        root_key,
        root_subject,
        root_key_id,
        root,
        issuing_key,
        issuing_subject,
        issuing_key_id,
        issuing,
    }
}

fn leaf(
    chain: &Chain,
    key: &PrivateKey,
    common_name: Option<&str>,
    names: SubjectAltNames,
    usage: &str,
    now: f64,
) -> (String, Vec<u8>) {
    let serial = random_serial();
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: serial.clone(),
            issuer: chain.issuing_subject.clone(),
            subject: common_name
                .map(DistinguishedName::common)
                .unwrap_or_default(),
            spki: key.spki().unwrap(),
            not_before: now - 60_000.0,
            not_after: now + 3_600_000.0,
            names: Some(names),
            usage: Some(usage.into()),
            authority_key_id: Some(chain.issuing_key_id.clone()),
            crl_url: Some("https://pki.acme.test/crl/workloads.crl".into()),
            ..CertificateSpec::default()
        },
        "ES256",
    )
    .unwrap();
    (
        serial,
        signed_structure(&tbs, "ES256", &sign(&chain.issuing_key, &tbs)),
    )
}

#[test]
fn certificates_read_back_as_node_reads_them() {
    let now = better_iam_server::utils::date_now();
    let chain = chain(now);
    let root = X509Certificate::from_der(&chain.root).unwrap();
    let issuing =
        X509Certificate::from_pem(&certificate_pem(&chain.issuing)).expect("intermediate PEM");
    assert!(root.ca() && issuing.ca());
    assert_eq!(
        root.subject().as_deref(),
        Some("C=US\nO=Acme\nCN=Acme Root CA")
    );
    assert!(root.verify(root.public_key()));
    assert!(issuing.check_issued(&root));
    assert!(issuing.verify(root.public_key()));
    assert!(!root.check_issued(&issuing));
    assert!(!issuing.verify(issuing.public_key()));
    assert_eq!(
        root.valid_from(),
        ((now - 60_000.0) / 1000.0).floor() * 1000.0
    );

    let server_key = key_pair("p256");
    let names = subject_alt_names(&json!({
        "dnsNames": ["localhost", "api.internal"],
        "ipAddresses": ["127.0.0.1", "::1"],
        "emails": ["ops@acme.internal"],
    }))
    .unwrap();
    let (serial, der) = leaf(&chain, &server_key, Some("localhost"), names, "server", now);
    let server = X509Certificate::from_der(&der).unwrap();
    assert!(!server.ca());
    assert_eq!(server.serial_number(), serial.to_uppercase());
    assert_eq!(server.subject().as_deref(), Some("CN=localhost"));
    assert_eq!(
        server.subject_alt_name().as_deref(),
        Some(
            "email:ops@acme.internal, DNS:localhost, DNS:api.internal, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1"
        )
    );
    assert!(server.check_issued(&issuing) && server.verify(issuing.public_key()));
    assert!(!server.verify(root.public_key()));
    assert_eq!(server.public_key(), server_key.spki().unwrap());
    assert_eq!(
        server.valid_to(),
        ((now + 3_600_000.0) / 1000.0).floor() * 1000.0
    );

    // A SPIFFE SVID: empty subject (Node's undefined), one critical URI.
    let (_, der) = leaf(
        &chain,
        &key_pair("ed25519"),
        None,
        SubjectAltNames {
            uris: vec!["spiffe://acme.test/service/abc".into()],
            ..SubjectAltNames::default()
        },
        "both",
        now,
    );
    let svid = X509Certificate::from_der(&der).unwrap();
    assert_eq!(svid.subject(), None);
    assert_eq!(
        svid.subject_alt_name().as_deref(),
        Some("URI:spiffe://acme.test/service/abc")
    );
    // A tampered certificate no longer verifies.
    let mut tampered = der.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 0x01;
    if let Some(certificate) = X509Certificate::from_der(&tampered) {
        assert!(!certificate.verify(issuing.public_key()));
    }
    let _ = (&chain.root_key, &chain.root_subject, &chain.root_key_id);
}

#[test]
fn crls_list_revoked_serials_with_reasons() {
    let now = 1_792_410_254_421.0;
    let chain = chain(now);
    let serial = "11296d47338b003e1c6698743c8ad475";
    let tbs = tbs_cert_list(
        &CertListSpec {
            issuer: chain.issuing_subject.clone(),
            this_update: now,
            next_update: now + DAY,
            crl_number: 2.0,
            authority_key_id: chain.issuing_key_id.clone(),
            revoked: vec![
                RevokedEntry {
                    serial_number: serial.into(),
                    revoked_at: now,
                    reason: Some("keyCompromise".into()),
                },
                RevokedEntry {
                    serial_number: "2a".into(),
                    revoked_at: now,
                    reason: Some("unspecified".into()),
                },
            ],
        },
        "ES256",
    );
    let der = signed_structure(&tbs, "ES256", &sign(&chain.issuing_key, &tbs));
    let serial_bytes = hex::decode(serial).unwrap();
    assert!(der.windows(serial_bytes.len()).any(|w| w == serial_bytes));
    // keyCompromise is reason code 1; `unspecified` carries no reason extension.
    assert!(der.windows(3).any(|w| w == [0x0a, 0x01, 0x01]));
    assert_eq!(
        der.windows(5)
            .filter(|w| *w == [0x06, 0x03, 0x55, 0x1d, 0x15])
            .count(),
        1
    );
    // Version 2 (encoded 1), then ES256, as the CRLs of the TypeScript traces start.
    let root = better_iam_server::x509::read_root(&tbs).unwrap();
    assert_eq!(
        &tbs[root.content_start..root.content_start + 15],
        &[
            0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
            0x02
        ]
    );
    assert_eq!(sha256_fingerprint(b"").len(), 64);
}

// ---------------------------------------------------------------------------------------------------------------
// Stored authorities and certificates (seeded as createAuthority and issueCertificate store them)

/// An authority seeded in the store.
struct Seeded {
    id: String,
    key: p256::SecretKey,
    subject_der: Vec<u8>,
    key_id: Vec<u8>,
    pem: String,
    /// Its own certificate's serial (recorded under its parent for intermediates).
    serial: String,
}

struct AuthoritySeed<'a> {
    name: &'a str,
    parent: Option<&'a Seeded>,
    path_length: Option<f64>,
    trust_domain: Option<&'a str>,
    permitted: Option<PermittedNames>,
}

async fn seed_authority(f: &Org, tenant_id: &str, seed: AuthoritySeed<'_>) -> Seeded {
    let now = f.now();
    let key = p256_secret();
    let spki = PrivateKey::P256(key.clone()).spki().unwrap();
    let subject = DistinguishedName::common(&format!("{} CA", seed.name));
    let subject_der = encode_name(&subject);
    let key_id = key_identifier(&spki).unwrap();
    let serial = random_serial();
    let not_after = now + 3650.0 * DAY;
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: serial.clone(),
            issuer: seed
                .parent
                .map(|parent| parent.subject_der.clone())
                .unwrap_or_else(|| subject_der.clone()),
            subject: subject.clone(),
            spki,
            not_before: now - 60_000.0,
            not_after,
            ca: Some(CaSpec {
                path_length: seed.path_length,
            }),
            authority_key_id: seed.parent.map(|parent| parent.key_id.clone()),
            permitted: seed.parent.and(seed.permitted.clone()),
            ..CertificateSpec::default()
        },
        "ES256",
    )
    .unwrap();
    let signer = seed.parent.map(|parent| &parent.key).unwrap_or(&key);
    let der = signed_structure(&tbs, "ES256", &sign(signer, &tbs));
    let pem = certificate_pem(&der);
    let id = better_iam_server::utils::id();
    let mut record = json!({
        "id": id,
        "tenantId": tenant_id,
        "uniqueKey": format!("name:{}", seed.name.to_lowercase()),
        "name": seed.name,
        "type": if seed.parent.is_some() { "intermediate" } else { "root" },
        "subject": { "commonName": format!("{} CA", seed.name) },
        "subjectDer": b64(&subject_der),
        "subjectKeyId": hex::encode(&key_id),
        "keyId": better_iam_server::utils::id(),
        "keyVersion": 1,
        "algorithm": "ES256",
        "certificatePem": pem,
        "serialNumber": serial,
        "notBefore": now - 60_000.0,
        "notAfter": not_after,
        "state": "active",
        "maxValiditySeconds": 90 * 86_400,
        "defaultValiditySeconds": 86_400,
        "revision": 0,
        "crlNumber": 0,
        "createdAt": now,
        "createdBy": f.owner_id,
        "updatedAt": now,
    });
    if let Some(parent) = seed.parent {
        record["parentId"] = json!(parent.id);
    }
    if let Some(path_length) = seed.path_length {
        record["pathLength"] = json!(path_length);
    }
    if let Some(domain) = seed.trust_domain {
        record["trustDomain"] = json!(domain);
    }
    if let Some(permitted) = &seed.permitted {
        record["permitted"] = serde_json::to_value(permitted).unwrap();
    }
    f.insert("pkiAuthorities", record).await;
    if let Some(parent) = seed.parent {
        f.insert(
            "pkiCertificates",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "uniqueKey": format!("serial:{serial}"),
                "authorityId": parent.id,
                "serialNumber": serial,
                "commonName": format!("{} CA", seed.name),
                "names": { "dnsNames": [], "uris": [], "ipAddresses": [], "emails": [] },
                "keyType": "ecc-p256",
                "usage": "ca",
                "notBefore": now - 60_000.0,
                "notAfter": not_after,
                "certificatePem": pem,
                "fingerprint": sha256_fingerprint(&der),
                "subordinateId": id,
                "status": "valid",
                "issuedAt": now,
                "issuedBy": f.owner_id,
            }),
        )
        .await;
    }
    Seeded {
        id,
        key,
        subject_der,
        key_id,
        pem,
        serial,
    }
}

struct LeafSeed<'a> {
    common_name: Option<&'a str>,
    names: Value,
    usage: &'a str,
    identity_id: Option<&'a str>,
    spiffe_id: Option<&'a str>,
}

/// A leaf as `issueCertificate` / `requestCertificate` store it; returns its PEM and serial.
async fn seed_leaf(
    f: &Org,
    tenant_id: &str,
    authority: &Seeded,
    seed: LeafSeed<'_>,
) -> (String, String) {
    let now = f.now();
    let key = key_pair("p256");
    let names = subject_alt_names(&seed.names).unwrap();
    let serial = random_serial();
    let not_after = now + 3_600_000.0;
    let tbs = tbs_certificate(
        &CertificateSpec {
            serial_number: serial.clone(),
            issuer: authority.subject_der.clone(),
            subject: seed
                .common_name
                .map(DistinguishedName::common)
                .unwrap_or_default(),
            spki: key.spki().unwrap(),
            not_before: now - 60_000.0,
            not_after,
            names: Some(names.clone()),
            usage: Some(seed.usage.into()),
            authority_key_id: Some(authority.key_id.clone()),
            ..CertificateSpec::default()
        },
        "ES256",
    )
    .unwrap();
    let der = signed_structure(&tbs, "ES256", &sign(&authority.key, &tbs));
    let pem = certificate_pem(&der);
    let mut record = json!({
        "id": better_iam_server::utils::id(),
        "tenantId": tenant_id,
        "uniqueKey": format!("serial:{serial}"),
        "authorityId": authority.id,
        "serialNumber": serial,
        "names": names.to_value(),
        "keyType": "ecc-p256",
        "usage": seed.usage,
        "notBefore": now - 60_000.0,
        "notAfter": not_after,
        "certificatePem": pem,
        "fingerprint": sha256_fingerprint(&der),
        "status": "valid",
        "issuedAt": now,
        "issuedBy": f.owner_id,
    });
    if let Some(name) = seed.common_name {
        record["commonName"] = json!(name);
    }
    if let Some(identity_id) = seed.identity_id {
        record["identityId"] = json!(identity_id);
    }
    if let Some(spiffe_id) = seed.spiffe_id {
        record["spiffeId"] = json!(spiffe_id);
    }
    f.insert("pkiCertificates", record).await;
    (pem, serial)
}

/// The root and issuing authorities of tests/pki.test.ts, seeded.
async fn authorities(f: &Org) -> (Seeded, Seeded) {
    let root = seed_authority(
        f,
        &f.tenant_id,
        AuthoritySeed {
            name: "Acme Root",
            parent: None,
            path_length: Some(1.0),
            trust_domain: None,
            permitted: None,
        },
    )
    .await;
    f.advance(1000.0);
    let issuing = seed_authority(
        f,
        &f.tenant_id,
        AuthoritySeed {
            name: "Acme Workloads",
            parent: Some(&root),
            path_length: Some(0.0),
            trust_domain: Some("acme.test"),
            permitted: Some(PermittedNames {
                dns_names: strings(&["internal", "localhost"]),
                uri_hosts: strings(&["acme.test"]),
            }),
        },
    )
    .await;
    (root, issuing)
}

async fn verify(f: &Org, chain: Value, options: Value) -> Result<Value, better_iam_core::IamError> {
    f.iam
        .pki
        .verify(&chain, &options)
        .await
        .map(|verified| verified.to_value())
}

#[test]
fn verifies_stored_chains_per_tenant_and_revokes_subordinates() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (root, issuing) = authorities(&f).await;
        let (client_pem, client_serial) = seed_leaf(
            &f,
            &f.tenant_id,
            &issuing,
            LeafSeed {
                common_name: None,
                names: json!({ "uris": ["spiffe://acme.test/billing"] }),
                usage: "client",
                identity_id: None,
                spiffe_id: None,
            },
        )
        .await;
        // Verification for the server side of mTLS: the stored chain, not what the client sent.
        let verified = verify(
            &f,
            json!(client_pem),
            json!({ "tenantId": f.tenant_id, "usage": "client" }),
        )
        .await
        .unwrap();
        assert_matches(
            &verified,
            json!({
                "tenantId": f.tenant_id,
                "authorityId": issuing.id,
                "serialNumber": client_serial,
                "subject": "",
                "dnsNames": [],
                "uris": ["spiffe://acme.test/billing"],
            }),
        );
        assert!(verified.get("spiffeId").is_none());
        // Intermediates in the presented chain are ignored; a list works as well as a concatenation.
        verify(
            &f,
            json!([format!("{client_pem}{}", issuing.pem)]),
            json!({ "tenantId": f.tenant_id }),
        )
        .await
        .unwrap();
        let error = verify(
            &f,
            json!(client_pem),
            json!({ "tenantId": f.tenant_id, "usage": "server" }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str(), error.status),
            (
                "CERTIFICATE_INVALID",
                "The certificate is not for server use",
                401
            )
        );
        // A CA certificate never authenticates.
        let error = verify(&f, json!(issuing.pem), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "A CA certificate cannot authenticate");
        let error = verify(&f, json!(root.pem), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "The certificate was not issued here");
        let error = verify(&f, json!("nothing"), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "No certificate was presented");
        let error = verify(
            &f,
            json!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
            json!({ "tenantId": f.tenant_id }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.message, "The certificate cannot be read");
        let error = verify(
            &f,
            json!(client_pem),
            json!({ "tenantId": f.tenant_id, "at": f.now() + 2.0 * 3_600_000.0 }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.message, "The certificate is not valid at this time");
        // Verification is per tenant, and needs one.
        let (globex, _, _) = f
            .activate(
                &f.root_tenant.clone(),
                "Globex",
                "organization",
                "owner@globex.test",
            )
            .await;
        let error = verify(&f, json!(client_pem), json!({ "tenantId": globex }))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "CERTIFICATE_INVALID");
        let error = verify(&f, json!(client_pem), Value::Null)
            .await
            .unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid tenantId")
        );
        let error = f
            .iam
            .pki
            .call(
                "verify",
                vec![json!(client_pem), json!({ "$undefined": true })],
            )
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(code(&error), "INVALID_INPUT");

        // Revoking the intermediate's certificate at the root revokes the authority and everything it issued.
        let pki = &f.iam.api.pki;
        let error = fails(
            pki.revoke_certificate(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "serialNumber": issuing.serial, "reason": "certificateHold" })),
            )
            .await,
        );
        assert_eq!(error.message, "Unknown revocation reason");
        let revoked = ok(pki
            .revoke_certificate(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "serialNumber": issuing.serial.to_uppercase(),
                    "reason": "caCompromise",
                })),
            )
            .await);
        assert_matches(
            &revoked,
            json!({
                "authorityId": root.id,
                "subordinateId": issuing.id,
                "status": "revoked",
                "revocationReason": "caCompromise",
                "usage": "ca",
            }),
        );
        let authority = ok(pki
            .get_authority(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "authorityId": issuing.id })),
            )
            .await);
        assert_eq!(authority["state"], "revoked");
        let error = verify(&f, json!(client_pem), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "An issuing authority is not active");
        let error = fails(
            pki.revoke_certificate(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "serialNumber": issuing.serial })),
            )
            .await,
        );
        assert_eq!((code(&error), error.status), ("CONFLICT", 409));
        let error = fails(
            pki.update_authority(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "authorityId": issuing.id, "state": "active" })),
            )
            .await,
        );
        assert_eq!(code(&error), "AUTHORITY_UNAVAILABLE");
        // The root's revision moved, so its next CRL is rebuilt; the revocation is audited with the cascade.
        let stored = f
            .find("pkiAuthorities", Filter::new().eq("id", root.id.clone()))
            .await;
        assert_eq!(stored[0]["revision"], json!(1));
        let events = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await;
        assert!(events.iter().any(|event| {
            event["action"] == "iam:pki:revoke"
                && event["outcome"] == "allow"
                && event["metadata"]["serialNumber"] == json!(issuing.serial)
                && event["metadata"]["authoritiesRevoked"] == json!(1)
                && event["metadata"]["authorityId"] == json!(root.id)
        }));
        // A refusal after authorization is evidence too.
        assert!(events.iter().any(|event| {
            event["action"] == "iam:pki:update"
                && event["outcome"] == "deny"
                && event["metadata"]["reason"] == "authority-unavailable"
        }));
    });
}

#[test]
fn workload_certificates_stop_with_their_identity() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_root, issuing) = authorities(&f).await;
        let person = f.member("pat").await;
        let spiffe_id = format!("spiffe://acme.test/user/{person}");
        let (pem, _) = seed_leaf(
            &f,
            &f.tenant_id,
            &issuing,
            LeafSeed {
                common_name: None,
                names: json!({ "uris": [spiffe_id] }),
                usage: "both",
                identity_id: Some(&person),
                spiffe_id: Some(&spiffe_id),
            },
        )
        .await;
        let verified = verify(&f, json!(pem), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap();
        assert_matches(
            &verified,
            json!({ "identityId": person, "spiffeId": spiffe_id, "tenantId": f.tenant_id }),
        );
        let keys: Vec<&String> = verified.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "tenantId",
                "authorityId",
                "serialNumber",
                "fingerprint",
                "subject",
                "dnsNames",
                "uris",
                "notAfter",
                "spiffeId",
                "identityId"
            ]
        );
        let mut identity = f
            .find("identities", Filter::new().eq("id", person.clone()))
            .await
            .remove(0);
        identity.insert("status".into(), json!("disabled"));
        f.put("identities", identity).await;
        let error = verify(&f, json!(pem), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "The identity it names is no longer active");
    });
}

#[test]
fn lists_gets_updates_and_bundles_authorities() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (root, issuing) = authorities(&f).await;
        let pki = &f.iam.api.pki;
        let owner = &f.owner_credential;
        let tenant = f.tenant_id.clone();
        f.advance(1000.0);
        let (_, first) = seed_leaf(
            &f,
            &tenant,
            &issuing,
            LeafSeed {
                common_name: Some("a.internal"),
                names: json!({ "dnsNames": ["a.internal"] }),
                usage: "server",
                identity_id: None,
                spiffe_id: None,
            },
        )
        .await;
        f.advance(1000.0);
        let (_, second) = seed_leaf(
            &f,
            &tenant,
            &issuing,
            LeafSeed {
                common_name: None,
                names: json!({ "dnsNames": ["b.internal"] }),
                usage: "both",
                identity_id: None,
                spiffe_id: None,
            },
        )
        .await;
        let listed = ok(pki
            .list_authorities(owner, body(json!({ "tenantId": tenant })))
            .await);
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|authority| authority["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Acme Root", "Acme Workloads"]);
        assert_matches(
            &listed[1],
            json!({
                "type": "intermediate",
                "parentId": root.id,
                "trustDomain": "acme.test",
                "state": "active",
                "pathLength": 0,
                "permitted": { "dnsNames": ["internal", "localhost"], "uriHosts": ["acme.test"] },
            }),
        );
        // The intermediate's own certificate is recorded under the root, so the root can revoke it.
        let under_root = ok(pki
            .list_certificates(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": root.id })),
            )
            .await);
        assert_eq!(under_root["total"], 1);
        assert_matches(
            &under_root["certificates"][0],
            json!({ "usage": "ca", "subordinateId": issuing.id, "status": "valid" }),
        );
        // Newest first, with paging.
        let leaves = ok(pki
            .list_certificates(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing.id, "limit": 1 })),
            )
            .await);
        assert_eq!(leaves["total"], 2);
        assert_eq!(leaves["certificates"][0]["serialNumber"], json!(second));
        let page = ok(pki
            .list_certificates(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing.id, "limit": 1, "offset": 1 })),
            )
            .await);
        assert_eq!(page["certificates"][0]["serialNumber"], json!(first));
        let expired = ok(pki
            .list_certificates(
                owner,
                body(json!({ "tenantId": tenant, "status": "expired" })),
            )
            .await);
        assert_eq!(expired["total"], 0);
        let error = fails(
            pki.list_certificates(owner, body(json!({ "tenantId": tenant, "limit": 0 })))
                .await,
        );
        assert_eq!(error.message, "Invalid limit");
        // One certificate by serial number, in any common spelling.
        let colons = first
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        let found = ok(pki
            .get_certificate(
                owner,
                body(json!({ "tenantId": tenant, "serialNumber": colons })),
            )
            .await);
        assert_matches(
            &found,
            json!({ "serialNumber": first, "commonName": "a.internal", "usage": "server", "status": "valid" }),
        );
        let keys: Vec<&String> = found.as_object().unwrap().keys().collect();
        assert_eq!(keys[..4], ["id", "tenantId", "authorityId", "serialNumber"]);
        assert_eq!(keys.last().unwrap().as_str(), "commonName");
        let error = fails(
            pki.get_certificate(
                owner,
                body(json!({ "tenantId": tenant, "serialNumber": "zz" })),
            )
            .await,
        );
        assert_eq!(error.message, "serialNumber must be hexadecimal");
        let error = fails(
            pki.get_certificate(
                owner,
                body(json!({ "tenantId": tenant, "serialNumber": "abc" })),
            )
            .await,
        );
        assert_eq!((code(&error), error.status), ("NOT_FOUND", 404));
        // Updates: state, validity limits (the default never above the maximum), the CRL URL.
        let error = fails(
            pki.update_authority(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing.id, "state": "revoked" })),
            )
            .await,
        );
        assert_eq!(error.message, "state must be active or disabled");
        let updated = ok(pki
            .update_authority(
                owner,
                body(json!({
                    "tenantId": tenant,
                    "authorityId": issuing.id,
                    "state": "disabled",
                    "maxValiditySeconds": 3600,
                    "crlUrl": "https://pki.acme.test/crl/b.crl",
                })),
            )
            .await);
        assert_matches(
            &updated,
            json!({
                "state": "disabled",
                "maxValiditySeconds": 3600,
                "defaultValiditySeconds": 3600,
                "crlUrl": "https://pki.acme.test/crl/b.crl",
            }),
        );
        let cleared = ok(pki
            .update_authority(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing.id, "crlUrl": null, "state": "active" })),
            )
            .await);
        assert!(cleared.get("crlUrl").is_none());
        assert_eq!(cleared["state"], "active");
        let error = fails(
            pki.update_authority(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing.id, "crlUrl": "ftp://x" })),
            )
            .await,
        );
        assert_eq!(error.message, "crlUrl must be an http(s) URL");
        // Only roots are trust anchors; intermediates travel in each server's chain.
        let bundle = ok(pki.bundle(owner, body(json!({ "tenantId": tenant }))).await);
        assert_eq!(bundle["authorities"], 1);
        assert_eq!(bundle["pem"], json!(root.pem));
        assert_eq!(f.iam.pki.bundle(&tenant).await.unwrap(), root.pem);
        // Unknown authorities, and authorities of another tenant, are not found.
        let error = fails(
            pki.get_authority(
                owner,
                body(json!({ "tenantId": tenant, "authorityId": "missing" })),
            )
            .await,
        );
        assert_eq!((code(&error), error.status), ("NOT_FOUND", 404));
        let member = f.member("una").await;
        let una = f.sign_in(&member).await;
        let error = fails(
            pki.get_authority(
                &una,
                body(json!({ "tenantId": tenant, "authorityId": root.id })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let nothing = ok(pki
            .list_authorities(&una, body(json!({ "tenantId": tenant })))
            .await);
        assert_eq!(nothing, json!([]));
    });
}

#[test]
fn crl_responses_for_unknown_authorities_are_not_found() {
    run(|| async {
        let f = organization(|_| {}).await;
        let response = f.iam.pki.crl_response("missing").await.unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.body().as_ref(), b"Not found");
        assert_eq!(
            f.iam
                .pki
                .call("crlResponse", vec![json!("missing")])
                .await
                .unwrap()
                .unwrap(),
            json!({ "$object": "Response" })
        );
        let error = f.iam.pki.crl("missing").await.unwrap_err();
        assert_eq!(error.message, "Certificate authority not found");
        // A cached CRL is served as stored while nothing changed and it is fresh.
        let (_root, issuing) = authorities(&f).await;
        let mut record = f
            .find("pkiAuthorities", Filter::new().eq("id", issuing.id.clone()))
            .await
            .remove(0);
        record.insert(
            "crl".into(),
            json!({ "der": "MAMCAQE=", "thisUpdate": f.now(), "nextUpdate": f.now() + DAY, "revision": 0, "crlNumber": 3 }),
        );
        f.put("pkiAuthorities", record).await;
        let crl = f
            .iam
            .pki
            .call("crl", vec![json!(issuing.id)])
            .await
            .unwrap()
            .unwrap();
        assert_matches(
            &crl,
            json!({ "der": { "$bytes": "MAMCAQE=" }, "revision": 0, "crlNumber": 3 }),
        );
        assert!(
            crl["pem"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN X509 CRL-----\nMAMCAQE=\n")
        );
        let response = f.iam.pki.crl_response(&issuing.id).await.unwrap();
        assert_eq!(response.headers()["content-type"], "application/pkix-crl");
        assert_eq!(response.headers()["cache-control"], "public, max-age=43200");
        assert_eq!(response.body().as_ref(), [0x30, 0x03, 0x02, 0x01, 0x01]);
    });
}

// ---------------------------------------------------------------------------------------------------------------
// tests/pki.test.ts and tests/pki-security.test.ts (authorities created through the API: they need kms.ts)

const NEEDS_KMS: &str = "needs the kms.ts port (createServiceKey, kmsSignFor)";

/// `authorities(f)` of tests/pki.test.ts, through the API.
async fn api_authorities(f: &Org) -> (CredentialInput, Value, Value) {
    let owner = f.session(&f.owner_id, false).await;
    let pki = &f.iam.api.pki;
    let root = ok(pki
        .create_authority(
            &owner,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Acme Root",
                "subject": { "commonName": "Acme Root CA", "organization": "Acme", "country": "US" },
                "pathLength": 1,
            })),
        )
        .await);
    let issuing = ok(pki
        .create_authority(
            &owner,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Acme Workloads",
                "parentId": root["id"],
                "subject": { "commonName": "Acme Workload CA", "organization": "Acme" },
                "trustDomain": "acme.test",
                "permitted": { "dnsNames": ["internal", "localhost"], "uriHosts": ["acme.test"] },
                "crlUrl": "https://pki.acme.test/crl/workloads.crl",
            })),
        )
        .await);
    (owner, root, issuing)
}

fn pem_of(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn creates_a_root_and_an_intermediate_that_read_and_verify() {
    let _ = NEEDS_KMS;
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let root_cert = X509Certificate::from_pem(&pem_of(&root["certificatePem"])).unwrap();
        let issuing_cert = X509Certificate::from_pem(&pem_of(&issuing["certificatePem"])).unwrap();
        assert!(root_cert.ca() && issuing_cert.ca());
        assert!(root_cert.subject().unwrap().contains("CN=Acme Root CA"));
        assert!(root_cert.verify(root_cert.public_key()));
        assert!(issuing_cert.check_issued(&root_cert));
        assert!(issuing_cert.verify(root_cert.public_key()));
        assert_matches(
            &issuing,
            json!({ "type": "intermediate", "parentId": root["id"], "trustDomain": "acme.test", "state": "active" }),
        );
        // The signing keys are KMS keys, visible and tagged.
        let key = ok(f
            .iam
            .api
            .keys
            .get(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "keyId": root["keyId"] })),
            )
            .await);
        assert_matches(
            &key,
            json!({ "keySpec": "ecc-p256", "keyUsage": "sign", "tags": { "pki-authority": "Acme Root" } }),
        );
        let under_root = ok(pki
            .list_certificates(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "authorityId": root["id"] })),
            )
            .await);
        assert_matches(
            &under_root["certificates"][0],
            json!({ "usage": "ca", "subordinateId": issuing["id"] }),
        );
        // Path length 1 under the root leaves none below the intermediate.
        let error = fails(
            pki.create_authority(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Too deep",
                    "parentId": root["id"],
                    "subject": { "commonName": "Too deep" },
                    "pathLength": 1,
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let bundle = ok(pki
            .bundle(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(bundle["authorities"], 1);
        assert!(
            bundle["pem"]
                .as_str()
                .unwrap()
                .starts_with(&pem_of(&root["certificatePem"]))
        );
        assert_eq!(
            json!(f.iam.pki.bundle(&f.tenant_id).await.unwrap()),
            bundle["pem"]
        );
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn issues_certificates_from_requests() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let server_key = key_pair("p256");
        let server = ok(pki
            .issue_certificate(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "authorityId": issuing["id"],
                    "csr": csr(server_key.clone(), Some("localhost"), &["localhost", "api.internal"], &[], &["127.0.0.1"]),
                    "usage": "server",
                    "validitySeconds": 3600,
                })),
            )
            .await);
        let leaf = X509Certificate::from_pem(&pem_of(&server["certificatePem"])).unwrap();
        let issuing_cert = X509Certificate::from_pem(&pem_of(&issuing["certificatePem"])).unwrap();
        assert!(!leaf.ca());
        assert!(
            leaf.subject_alt_name()
                .unwrap()
                .contains("DNS:api.internal")
        );
        assert!(
            leaf.subject_alt_name()
                .unwrap()
                .contains("IP Address:127.0.0.1")
        );
        assert!(leaf.verify(issuing_cert.public_key()));
        assert_eq!(leaf.public_key(), server_key.spki().unwrap());
        assert_eq!(server["chainPem"], issuing["certificatePem"]);
        assert_eq!(server["rootPem"], root["certificatePem"]);
        assert!(leaf.valid_to() - f.now() <= 3_600_000.0);
        let client = ok(pki
            .issue_certificate(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "authorityId": issuing["id"],
                    "csr": csr(key_pair("ed25519"), None, &[], &["spiffe://acme.test/billing"], &[]),
                    "usage": "client",
                })),
            )
            .await);
        let verified = verify(
            &f,
            client["certificatePem"].clone(),
            json!({ "tenantId": f.tenant_id, "usage": "client" }),
        )
        .await
        .unwrap();
        assert_matches(
            &verified,
            json!({ "serialNumber": client["serialNumber"], "uris": ["spiffe://acme.test/billing"] }),
        );
        let error = verify(
            &f,
            client["certificatePem"].clone(),
            json!({ "tenantId": f.tenant_id, "usage": "server" }),
        )
        .await
        .unwrap_err();
        assert_eq!(code(&error), "CERTIFICATE_INVALID");
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn decides_every_name_and_enforces_name_constraints_and_spiffe_rules() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let person = f.member("pat").await;
        f.grant(
            &person,
            json!([{
                "effect": "allow",
                "actions": ["iam:pki:issue"],
                "resources": ["iam/pki/*"],
                "conditions": {
                    "StringLike": { "resource.name": ["*.payments.internal", "payments.internal"] },
                    "NumericLessThanEquals": { "resource.validitySeconds": 86400 },
                },
            }]),
        )
        .await;
        let pat = f.sign_in(&person).await;
        let issue = |credential: CredentialInput, input: Value| {
            let mut input = input;
            input["tenantId"] = json!(f.tenant_id);
            input["authorityId"] = issuing["id"].clone();
            async move { pki.issue_certificate(&credential, body(input)).await }
        };
        ok(issue(
            pat.clone(),
            json!({ "csr": csr(key_pair("p256"), Some("api.payments.internal"), &["api.payments.internal"], &[], &[]) }),
        )
        .await);
        // One name outside the policy refuses the whole certificate.
        let error = fails(
            issue(
                pat.clone(),
                json!({ "csr": csr(key_pair("p256"), None, &["api.payments.internal", "admin.internal"], &[], &[]) }),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Validity is part of the decision too.
        let error = fails(
            issue(
                pat.clone(),
                json!({
                    "csr": csr(key_pair("p256"), None, &["api.payments.internal"], &[], &[]),
                    "validitySeconds": 7 * 86400,
                }),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Name constraints bind even the owner: `.internal` and `localhost` only.
        let error = fails(
            issue(
                owner.clone(),
                json!({ "csr": csr(key_pair("p256"), None, &["www.example.com"], &[], &[]) }),
            )
            .await,
        );
        assert_eq!(code(&error), "NAME_NOT_PERMITTED");
        let error = fails(
            issue(
                owner.clone(),
                json!({ "csr": csr(key_pair("p256"), None, &[], &["spiffe://other.test/x"], &[]) }),
            )
            .await,
        );
        assert_eq!(code(&error), "NAME_NOT_PERMITTED");
        let error = fails(
            issue(
                owner.clone(),
                json!({ "csr": csr(key_pair("p256"), None, &[], &["spiffe://acme.test/a", "https://acme.test/b"], &[]) }),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        // Validity beyond the authority's maximum is refused outright.
        let error = fails(
            issue(
                owner.clone(),
                json!({
                    "csr": csr(key_pair("p256"), None, &["a.internal"], &[], &[]),
                    "validitySeconds": 400 * 86400,
                }),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn refuses_tampered_requests_and_accepts_rsa_through_the_api() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let error = fails(
            pki.issue_certificate(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "authorityId": issuing["id"], "csr": "not a csr" })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_CSR");
        ok(pki
            .issue_certificate(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "authorityId": issuing["id"],
                    "csr": csr(key_pair("rsa"), None, &["rsa.internal"], &[], &[]),
                })),
            )
            .await);
    });
}

/// A service account with an API key that holds `statements`.
async fn workload(
    f: &Org,
    owner: &CredentialInput,
    statements: Value,
    expires_in: Option<f64>,
) -> (String, CredentialInput) {
    let account = ok(f
        .iam
        .api
        .service_accounts
        .create(
            owner,
            body(json!({ "tenantId": f.tenant_id, "name": "billing-job" })),
        )
        .await);
    let account_id = account["id"].as_str().unwrap().to_owned();
    f.grant(&account_id, statements).await;
    let mut input = json!({ "tenantId": f.tenant_id, "identityId": account_id, "name": "job" });
    if let Some(seconds) = expires_in {
        input["expiresInSeconds"] = json!(seconds);
    }
    let key = ok(f.iam.api.credentials.create(owner, body(input)).await);
    (account_id, bearer(key["token"].as_str().unwrap()))
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn gives_workloads_spiffe_certificates_revocable_with_a_crl() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let (account, key) = workload(
            &f,
            &owner,
            json!([{ "effect": "allow", "actions": ["iam:pki:request"], "resources": ["iam/pki/*"] }]),
            None,
        )
        .await;
        let svid = ok(pki
            .request_certificate(
                &key,
                body(json!({
                    "tenantId": f.tenant_id,
                    "authorityId": issuing["id"],
                    "csr": csr(key_pair("p256"), None, &["ignored.internal"], &[], &[]),
                })),
            )
            .await);
        assert_eq!(
            svid["spiffeId"],
            json!(format!("spiffe://acme.test/service/{account}"))
        );
        let certificate = X509Certificate::from_pem(&pem_of(&svid["certificatePem"])).unwrap();
        assert_eq!(
            certificate.subject_alt_name(),
            Some(format!("URI:{}", svid["spiffeId"].as_str().unwrap()))
        );
        assert_eq!(certificate.subject(), None);
        assert!(certificate.valid_to() - f.now() <= 3_600_000.0);
        let chained = format!(
            "{}{}",
            pem_of(&svid["certificatePem"]),
            pem_of(&svid["chainPem"])
        );
        let verified = verify(&f, json!(chained), json!({ "tenantId": f.tenant_id }))
            .await
            .unwrap();
        assert_matches(
            &verified,
            json!({ "identityId": account, "spiffeId": svid["spiffeId"], "tenantId": f.tenant_id }),
        );
        // Without iam:pki:request, a person gets nothing.
        let una = f.member("una").await;
        let una = f.sign_in(&una).await;
        let error = fails(
            pki.request_certificate(
                &una,
                body(json!({
                    "tenantId": f.tenant_id,
                    "authorityId": issuing["id"],
                    "csr": csr(key_pair("p256"), None, &[], &[], &[]),
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Revocation takes effect for verification at once, and lands on the CRL.
        let before = ok(pki
            .crl(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "authorityId": issuing["id"] })),
            )
            .await);
        ok(pki
            .revoke_certificate(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "serialNumber": svid["serialNumber"], "reason": "keyCompromise" })),
            )
            .await);
        let error = verify(
            &f,
            svid["certificatePem"].clone(),
            json!({ "tenantId": f.tenant_id }),
        )
        .await
        .unwrap_err();
        assert_eq!(code(&error), "CERTIFICATE_INVALID");
        let issuing_id = issuing["id"].as_str().unwrap();
        let after = f.iam.pki.crl(issuing_id).await.unwrap();
        assert_eq!(
            after.current.crl_number,
            before["crlNumber"].as_f64().unwrap() + 1.0
        );
        let serial = hex::decode(svid["serialNumber"].as_str().unwrap()).unwrap();
        assert!(after.current.der.windows(serial.len()).any(|w| w == serial));
        let response = f.iam.pki.crl_response(issuing_id).await.unwrap();
        assert_eq!(response.headers()["content-type"], "application/pkix-crl");
        assert_eq!(response.body().as_ref(), after.current.der.as_slice());
        // A cached CRL is served until something changes.
        assert_eq!(
            f.iam.pki.crl(issuing_id).await.unwrap().current.crl_number,
            after.current.crl_number
        );
        assert_eq!(
            f.iam.pki.crl_response("missing").await.unwrap().status(),
            404
        );
        let listed = ok(pki
            .list_certificates(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": account })),
            )
            .await);
        assert_matches(
            &listed["certificates"][0],
            json!({ "status": "revoked", "revocationReason": "keyCompromise" }),
        );
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn revokes_subordinate_authorities_pins_ca_keys_and_stops_with_a_disabled_key() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let keys = &f.iam.api.keys;
        let tenant = f.tenant_id.clone();
        let issue = |dns: &'static str| {
            let input = json!({
                "tenantId": tenant,
                "authorityId": issuing["id"],
                "csr": csr(key_pair("p256"), None, &[dns], &[], &[]),
            });
            let owner = owner.clone();
            async move { pki.issue_certificate(&owner, body(input)).await }
        };
        let leaf = ok(issue("a.internal").await);
        // Rotating the CA's KMS key does not change the authority: its pinned version keeps signing.
        ok(keys
            .rotate(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"] })),
            )
            .await);
        let again = ok(issue("b.internal").await);
        let issuing_cert = X509Certificate::from_pem(&pem_of(&issuing["certificatePem"])).unwrap();
        assert!(
            X509Certificate::from_pem(&pem_of(&again["certificatePem"]))
                .unwrap()
                .verify(issuing_cert.public_key())
        );
        // Disabling the KMS key stops the authority.
        ok(keys
            .disable(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"] })),
            )
            .await);
        assert_eq!(code(&fails(issue("c.internal").await)), "KEY_STATE_INVALID");
        ok(keys
            .enable(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"] })),
            )
            .await);
        // Revoking the intermediate's certificate at the root revokes the authority and everything it issued.
        let intermediate = ok(pki
            .list_certificates(
                &owner,
                body(json!({ "tenantId": tenant, "authorityId": root["id"] })),
            )
            .await)["certificates"][0]
            .clone();
        ok(pki
            .revoke_certificate(
                &owner,
                body(json!({ "tenantId": tenant, "serialNumber": intermediate["serialNumber"] })),
            )
            .await);
        let state = ok(pki
            .get_authority(
                &owner,
                body(json!({ "tenantId": tenant, "authorityId": issuing["id"] })),
            )
            .await)["state"]
            .clone();
        assert_eq!(state, "revoked");
        assert_eq!(
            code(
                &verify(
                    &f,
                    leaf["certificatePem"].clone(),
                    json!({ "tenantId": tenant })
                )
                .await
                .unwrap_err()
            ),
            "CERTIFICATE_INVALID"
        );
        assert_eq!(
            code(&fails(issue("d.internal").await)),
            "AUTHORITY_UNAVAILABLE"
        );
        let error = fails(
            pki.update_authority(
                &owner,
                body(
                    json!({ "tenantId": tenant, "authorityId": issuing["id"], "state": "active" }),
                ),
            )
            .await,
        );
        assert_eq!(code(&error), "AUTHORITY_UNAVAILABLE");
        // Audit: issuing and revoking are recorded with serial numbers, never keys.
        let events = f
            .find("audit", Filter::new().eq("tenantId", tenant.clone()))
            .await;
        assert!(events.iter().any(|event| {
            event["action"] == "iam:pki:issue"
                && event["metadata"]["serialNumber"] == leaf["serialNumber"]
        }));
        assert!(
            !serde_json::to_string(&events)
                .unwrap()
                .contains("PRIVATE KEY")
        );
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn never_lets_a_ca_key_sign_through_the_kms_api() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let keys = &f.iam.api.keys;
        let tenant = f.tenant_id.clone();
        let error = fails(
            keys.sign(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"], "message": "tbs" })),
            )
            .await,
        );
        assert_eq!(code(&error), "KEY_MANAGED");
        let error = fails(
            keys.sign_jwt(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"], "claims": {} })),
            )
            .await,
        );
        assert_eq!(code(&error), "KEY_MANAGED");
        let member = f.member("gus").await;
        let error = fails(
            keys.create_grant(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"], "granteeId": member, "operations": ["sign"] })),
            )
            .await,
        );
        assert_eq!(code(&error), "KEY_MANAGED");
        let key = ok(keys
            .get(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": issuing["keyId"] })),
            )
            .await);
        assert_matches(
            &key,
            json!({ "managedBy": "pki", "managedId": issuing["id"] }),
        );
        // Adopting an existing key takes it over; a key another authority owns cannot be adopted.
        let own = ok(keys
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "keySpec": "ed25519" })),
            )
            .await);
        ok(keys
            .sign(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": own["id"], "message": "before" })),
            )
            .await);
        ok(f.iam
            .api
            .pki
            .create_authority(
                &owner,
                body(json!({ "tenantId": tenant, "name": "Adopted", "subject": { "commonName": "Adopted Root" }, "keyId": own["id"] })),
            )
            .await);
        let error = fails(
            keys.sign(
                &owner,
                body(json!({ "tenantId": tenant, "keyId": own["id"], "message": "after" })),
            )
            .await,
        );
        assert_eq!(code(&error), "KEY_MANAGED");
        let error = fails(
            f.iam
                .api
                .pki
                .create_authority(
                    &owner,
                    body(json!({ "tenantId": tenant, "name": "Twin", "subject": { "commonName": "Twin Root" }, "keyId": own["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "KEY_MANAGED");
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn keeps_workload_certificates_within_the_credential_and_stops_them_with_the_identity() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let (account, key) = workload(
            &f,
            &owner,
            json!([{
                "effect": "allow",
                "actions": ["iam:pki:request"],
                "resources": ["iam/pki/*"],
                "conditions": {
                    "StringEquals": { "resource.identityKind": "service" },
                    "StringLike": { "resource.name": "spiffe://acme.test/service/*" },
                },
            }]),
            Some(30.0 * 60.0),
        )
        .await;
        let request = |validity: f64| {
            let input = json!({
                "tenantId": f.tenant_id,
                "authorityId": issuing["id"],
                "csr": csr(key_pair("p256"), None, &[], &[], &[]),
                "validitySeconds": validity,
            });
            let key = key.clone();
            async move { pki.request_certificate(&key, body(input)).await }
        };
        let svid = ok(request(86_400.0).await);
        // Asked for a day; the API key ends in 30 minutes, so the certificate does too.
        assert!(svid["notAfter"].as_f64().unwrap() <= f.now() + 30.0 * 60_000.0);
        assert_eq!(code(&fails(request(2.0 * 86_400.0).await)), "INVALID_INPUT");
        let verified = verify(
            &f,
            svid["certificatePem"].clone(),
            json!({ "tenantId": f.tenant_id }),
        )
        .await
        .unwrap();
        assert_eq!(verified["identityId"], json!(account));
        ok(f.iam
            .api
            .identities
            .set_status(
                &owner,
                body(
                    json!({ "tenantId": f.tenant_id, "identityId": account, "status": "disabled" }),
                ),
            )
            .await);
        let error = verify(
            &f,
            svid["certificatePem"].clone(),
            json!({ "tenantId": f.tenant_id }),
        )
        .await
        .unwrap_err();
        assert_eq!(code(&error), "CERTIFICATE_INVALID");
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn decides_and_encodes_the_same_canonical_names_through_the_api() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, _root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let issue = |csr: String| {
            let input =
                json!({ "tenantId": f.tenant_id, "authorityId": issuing["id"], "csr": csr });
            let owner = owner.clone();
            async move { pki.issue_certificate(&owner, body(input)).await }
        };
        let mapped = ok(issue(csr(
            key_pair("p256"),
            Some("db.internal"),
            &["db.internal"],
            &[],
            &["::ffff:10.0.0.1"],
        ))
        .await);
        assert!(
            X509Certificate::from_pem(&pem_of(&mapped["certificatePem"]))
                .unwrap()
                .subject_alt_name()
                .unwrap()
                .contains("IP Address:10.0.0.1")
        );
        // Identity paths are reserved for the identities themselves.
        let error = fails(
            issue(csr(
                key_pair("p256"),
                None,
                &[],
                &["spiffe://acme.test/service/someone-else"],
                &[],
            ))
            .await,
        );
        assert_eq!(code(&error), "NAME_NOT_PERMITTED");
        // The common name must be one of the alternative names, and name constraints cover it.
        let error = fails(
            issue(csr(
                key_pair("p256"),
                Some("www.example.com"),
                &["api.internal"],
                &[],
                &[],
            ))
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            issue(csr(
                key_pair("p256"),
                Some("www.example.com"),
                &[],
                &[],
                &[],
            ))
            .await,
        );
        assert_eq!(code(&error), "NAME_NOT_PERMITTED");
        // Refusals after authorization are audited.
        let denied = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await
            .into_iter()
            .filter(|event| {
                event["action"] == "iam:pki:issue"
                    && event["outcome"] == "deny"
                    && event["metadata"]["reason"] == "name-not-permitted"
            })
            .count();
        assert!(denied >= 2);
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn keeps_path_lengths_trust_anchors_and_trust_domains_straight() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (owner, root, issuing) = api_authorities(&f).await;
        let pki = &f.iam.api.pki;
        let tenant = f.tenant_id.clone();
        let create = |input: Value, credential: CredentialInput| async move {
            pki.create_authority(&credential, body(input)).await
        };
        assert_eq!(issuing["pathLength"], 0);
        let error = fails(
            create(
                json!({ "tenantId": tenant, "name": "Deeper", "parentId": issuing["id"], "subject": { "commonName": "Deeper" } }),
                owner.clone(),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let bundle = ok(pki
            .bundle(&owner, body(json!({ "tenantId": tenant })))
            .await);
        assert_matches(
            &bundle,
            json!({ "authorities": 1, "pem": root["certificatePem"] }),
        );
        let open = ok(create(json!({ "tenantId": tenant, "name": "Open root", "subject": { "commonName": "Open Root" } }), owner.clone()).await);
        let first = ok(create(json!({ "tenantId": tenant, "name": "First", "parentId": open["id"], "subject": { "commonName": "First" } }), owner.clone()).await);
        let second = ok(create(json!({ "tenantId": tenant, "name": "Second", "parentId": first["id"], "subject": { "commonName": "Second" } }), owner.clone()).await);
        let first_certificate = ok(pki
            .list_certificates(
                &owner,
                body(json!({ "tenantId": tenant, "authorityId": open["id"] })),
            )
            .await)["certificates"][0]
            .clone();
        ok(pki
            .revoke_certificate(
                &owner,
                body(json!({ "tenantId": tenant, "serialNumber": first_certificate["serialNumber"], "reason": "caCompromise" })),
            )
            .await);
        let state = ok(pki
            .get_authority(
                &owner,
                body(json!({ "tenantId": tenant, "authorityId": second["id"] })),
            )
            .await)["state"]
            .clone();
        assert_eq!(state, "revoked");
        // Another organization cannot claim the trust domain, and verification is per tenant.
        let (globex, _, globex_owner) = f
            .activate(
                &f.root_tenant.clone(),
                "Globex",
                "organization",
                "owner@globex.test",
            )
            .await;
        let error = fails(
            create(
                json!({ "tenantId": globex, "name": "Impostor", "subject": { "commonName": "Acme Issuing" }, "trustDomain": "acme.test" }),
                globex_owner,
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let leaf = ok(pki
            .issue_certificate(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "authorityId": issuing["id"],
                    "csr": csr(key_pair("p256"), Some("a.internal"), &["a.internal"], &[], &[]),
                })),
            )
            .await);
        let error = verify(
            &f,
            leaf["certificatePem"].clone(),
            json!({ "tenantId": globex }),
        )
        .await
        .unwrap_err();
        assert_eq!(code(&error), "CERTIFICATE_INVALID");
        let error = verify(&f, leaf["certificatePem"].clone(), Value::Null)
            .await
            .unwrap_err();
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs the kms.ts port (createServiceKey, kmsSignFor)"]
fn decides_wildcard_names_as_wildcards() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_owner, _root, issuing) = api_authorities(&f).await;
        let hosts = f.member("hosts").await;
        f.grant(
            &hosts,
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:pki:issue"],
                    "resources": ["iam/pki/*"],
                    "conditions": {
                        "StringEquals": { "resource.nameType": ["dns", "commonName"] },
                        "StringLike": { "resource.name": "*.internal" },
                    },
                },
                {
                    "effect": "deny",
                    "actions": ["iam:pki:issue"],
                    "resources": ["iam/pki/*"],
                    "conditions": { "StringEquals": { "resource.name": "vault.internal" } },
                },
            ]),
        )
        .await;
        let credential = f.sign_in(&hosts).await;
        let pki = &f.iam.api.pki;
        let issue = |dns: &'static str| {
            let input = json!({
                "tenantId": f.tenant_id,
                "authorityId": issuing["id"],
                "csr": csr(key_pair("p256"), None, &[dns], &[], &[]),
            });
            let credential = credential.clone();
            async move { pki.issue_certificate(&credential, body(input)).await }
        };
        ok(issue("api.internal").await);
        assert_eq!(code(&fails(issue("vault.internal").await)), "ACCESS_DENIED");
        // `*.internal` would cover vault.internal: it is decided as nameType `wildcard`, which nothing allowed.
        assert_eq!(code(&fails(issue("*.internal").await)), "ACCESS_DENIED");
    });
}

/// The refusals of tests/pki.test.ts and tests/pki-security.test.ts that happen before anything is signed, on seeded
/// authorities (so they run without kms.ts): authentication first, then policy per name, name constraints, SPIFFE
/// rules, validity limits and request parsing.
#[test]
fn refuses_issuance_before_signing() {
    run(|| async {
        let f = organization(|_| {}).await;
        let (_root, issuing) = authorities(&f).await;
        let pki = &f.iam.api.pki;
        let tenant = f.tenant_id.clone();
        let issue = |credential: CredentialInput, input: Value| {
            let mut input = input;
            input["tenantId"] = json!(tenant);
            if input.get("authorityId").is_none() {
                input["authorityId"] = json!(issuing.id);
            }
            async move { pki.issue_certificate(&credential, body(input)).await }
        };
        // A malformed request from someone without a valid credential never reaches the parser.
        let error = fails(
            issue(
                bearer("biam_ses_not-a-real-token"),
                json!({ "csr": "garbage" }),
            )
            .await,
        );
        assert_eq!(code(&error), "UNAUTHENTICATED");
        let nobody = f.member("nobody").await;
        f.grant(&nobody, json!([])).await;
        let nobody = f.sign_in(&nobody).await;
        let error = fails(
            issue(
                nobody,
                json!({ "csr": csr(key_pair("p256"), None, &["x.internal"], &[], &[]) }),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Every name is decided, and validity is part of the decision.
        let person = f.member("pat").await;
        f.grant(
            &person,
            json!([{
                "effect": "allow",
                "actions": ["iam:pki:issue"],
                "resources": ["iam/pki/*"],
                "conditions": {
                    "StringLike": { "resource.name": ["*.payments.internal", "payments.internal"] },
                    "NumericLessThanEquals": { "resource.validitySeconds": 86400 },
                },
            }]),
        )
        .await;
        let pat = f.sign_in(&person).await;
        let error = fails(
            issue(
                pat.clone(),
                json!({ "csr": csr(key_pair("p256"), None, &["api.payments.internal", "admin.internal"], &[], &[]) }),
            )
            .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("ACCESS_DENIED", "You may not certify admin.internal")
        );
        let error = fails(
            issue(
                pat.clone(),
                json!({
                    "csr": csr(key_pair("p256"), None, &["api.payments.internal"], &[], &[]),
                    "validitySeconds": 7 * 86400,
                }),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Wildcards are decided as wildcards, apart from the hosts they cover.
        let hosts = f.member("hosts").await;
        f.grant(
            &hosts,
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:pki:issue"],
                    "resources": ["iam/pki/*"],
                    "conditions": {
                        "StringEquals": { "resource.nameType": ["dns", "commonName"] },
                        "StringLike": { "resource.name": "*.internal" },
                    },
                },
                {
                    "effect": "deny",
                    "actions": ["iam:pki:issue"],
                    "resources": ["iam/pki/*"],
                    "conditions": { "StringEquals": { "resource.name": "vault.internal" } },
                },
            ]),
        )
        .await;
        let hosts = f.sign_in(&hosts).await;
        for dns in ["vault.internal", "*.internal"] {
            let error = fails(
                issue(
                    hosts.clone(),
                    json!({ "csr": csr(key_pair("p256"), None, &[dns], &[], &[]) }),
                )
                .await,
            );
            assert_eq!(code(&error), "ACCESS_DENIED", "{dns}");
        }
        // Name constraints and SPIFFE rules bind even the owner.
        let owner = f.session(&f.owner_id, false).await;
        let outside = "A requested name is outside the authority's name constraints";
        let refusals = [
            (
                json!({ "csr": csr(key_pair("p256"), None, &["www.example.com"], &[], &[]) }),
                "NAME_NOT_PERMITTED",
                outside,
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &[], &["spiffe://other.test/x"], &[]) }),
                "NAME_NOT_PERMITTED",
                "This authority issues SPIFFE IDs only in acme.test",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &[], &["spiffe://acme.test/a", "https://acme.test/b"], &[]) }),
                "INVALID_INPUT",
                "A SPIFFE certificate carries exactly one URI",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &["a.internal"], &[], &[]), "validitySeconds": 400 * 86400 }),
                "INVALID_INPUT",
                "Invalid validitySeconds",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &[], &["spiffe://acme.test/service/someone-else"], &[]) }),
                "NAME_NOT_PERMITTED",
                "spiffe://acme.test/service/\u{2026} names an identity; it is issued only to that identity (requestCertificate)",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), Some("www.example.com"), &["api.internal"], &[], &[]) }),
                "INVALID_INPUT",
                "The common name must be one of the subject alternative names",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), Some("www.example.com"), &[], &[], &[]) }),
                "NAME_NOT_PERMITTED",
                outside,
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &[], &[], &[]) }),
                "INVALID_INPUT",
                "A certificate needs a common name or at least one name",
            ),
            (
                json!({ "csr": "not a csr" }),
                "INVALID_CSR",
                "The certificate request is not valid DER",
            ),
            (
                json!({ "csr": 7 }),
                "INVALID_CSR",
                "csr must be a PEM certificate request",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &["a.internal"], &[], &[]), "usage": "mail" }),
                "INVALID_INPUT",
                "usage must be server, client or both",
            ),
            (
                json!({ "csr": csr(key_pair("p256"), None, &["a.internal"], &[], &[]), "authorityId": "missing" }),
                "NOT_FOUND",
                "Certificate authority not found",
            ),
        ];
        for (input, expected, message) in refusals {
            let error = fails(issue(owner.clone(), input).await);
            assert_eq!((code(&error), error.message.as_str()), (expected, message));
        }
        // Refusals after authorization are audited.
        let events = f
            .find("audit", Filter::new().eq("tenantId", tenant.clone()))
            .await;
        let denied = events
            .iter()
            .filter(|event| {
                event["action"] == "iam:pki:issue"
                    && event["outcome"] == "deny"
                    && event["metadata"]["reason"] == "name-not-permitted"
            })
            .count();
        assert!(denied >= 2);
        assert!(events.iter().any(|event| {
            event["action"] == "iam:pki:issue"
                && event["outcome"] == "deny"
                && event["metadata"]["reason"] == "refused"
        }));
    });
}
