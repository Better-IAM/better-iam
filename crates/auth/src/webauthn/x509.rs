//! X.509 helpers for attestation statements (`getCertificateInfo`, `convertX509PublicKeyToCOSE`,
//! `validateExtFIDOGenCEAAGUID`, `validateCertificatePath`, `isCertRevoked` of `@simplewebauthn/server`), on
//! `x509-cert` and RustCrypto.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, SubjectKeyIdentifier,
};
use x509_cert::name::Name;

use super::WebAuthnError;
use super::cbor::Cbor;
use super::cose::{self, Hash};

fn err(message: impl Into<String>) -> WebAuthnError {
    WebAuthnError(message.into())
}

/// Parses a DER certificate.
pub fn parse(der: &[u8]) -> Result<Certificate, WebAuthnError> {
    Certificate::from_der(der).map_err(|error| err(format!("Could not parse certificate: {error}")))
}

/// The text of a directory string attribute value (`AttributeValue.toString()`).
pub fn attribute_text(value: &AnyRef<'_>) -> String {
    match value.tag() {
        Tag::BmpString => {
            let units: Vec<u16> = value
                .value()
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(value.value()).into_owned(),
    }
}

/// The `C`, `O`, `OU` and `CN` of a name, from the first attribute of each relative distinguished name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameInfo {
    pub c: Option<String>,
    pub o: Option<String>,
    pub ou: Option<String>,
    pub cn: Option<String>,
    pub combined: String,
}

fn name_info(name: &Name) -> NameInfo {
    let mut info = NameInfo::default();
    for rdn in name.0.iter() {
        let Some(first) = rdn.0.iter().next() else {
            continue;
        };
        let text = AnyRef::from(&first.value);
        let value = attribute_text(&text);
        match first.oid.to_string().as_str() {
            "2.5.4.6" => info.c = Some(value),
            "2.5.4.10" => info.o = Some(value),
            "2.5.4.11" => info.ou = Some(value),
            "2.5.4.3" => info.cn = Some(value),
            _ => {}
        }
    }
    info.combined = [&info.c, &info.o, &info.ou, &info.cn]
        .iter()
        .filter_map(|part| part.as_deref().filter(|part| !part.is_empty()))
        .collect::<Vec<_>>()
        .join(" : ");
    info
}

/// A name as `@peculiar/x509` compares names: every attribute of every RDN, in order.
fn name_key(name: &Name) -> String {
    name.0
        .iter()
        .map(|rdn| {
            rdn.0
                .iter()
                .map(|attribute| {
                    format!(
                        "{}={}",
                        attribute.oid,
                        attribute_text(&AnyRef::from(&attribute.value))
                    )
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `getCertificateInfo(der)`.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub issuer: NameInfo,
    pub subject: NameInfo,
    /// The ASN.1 version value (2 for X.509 v3).
    pub version: u8,
    pub basic_constraints_ca: bool,
    pub not_before_ms: f64,
    pub not_after_ms: f64,
    pub certificate: Certificate,
}

/// The epoch milliseconds of a certificate time.
fn time_ms(time: &x509_cert::time::Time) -> f64 {
    time.to_unix_duration().as_millis() as f64
}

/// The extension with an OID, if present.
pub fn extension<'a>(
    certificate: &'a Certificate,
    oid: &str,
) -> Option<&'a x509_cert::ext::Extension> {
    let oid = ObjectIdentifier::new(oid).ok()?;
    certificate
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|extension| extension.extn_id == oid)
}

/// `getCertificateInfo(leafCertBuffer)`.
pub fn certificate_info(der: &[u8]) -> Result<CertificateInfo, WebAuthnError> {
    let certificate = parse(der)?;
    let tbs = &certificate.tbs_certificate;
    let mut basic_constraints_ca = false;
    if let Some(extension) = extension(&certificate, "2.5.29.19") {
        let constraints = BasicConstraints::from_der(extension.extn_value.as_bytes())
            .map_err(|error| err(error.to_string()))?;
        basic_constraints_ca = constraints.ca;
    }
    Ok(CertificateInfo {
        issuer: name_info(&tbs.issuer),
        subject: name_info(&tbs.subject),
        version: tbs.version as u8,
        basic_constraints_ca,
        not_before_ms: time_ms(&tbs.validity.not_before),
        not_after_ms: time_ms(&tbs.validity.not_after),
        certificate,
    })
}

/// `validateExtFIDOGenCEAAGUID(extensions, aaguid)`: when the leaf carries `id-fido-gen-ce-aaguid`, it must equal the
/// attested AAGUID.
pub fn validate_fido_aaguid(certificate: &Certificate, aaguid: &[u8]) -> Result<(), WebAuthnError> {
    let Some(extension) = extension(certificate, "1.3.6.1.4.1.45724.1.1.4") else {
        return Ok(());
    };
    let value = der::asn1::OctetString::from_der(extension.extn_value.as_bytes())
        .map_err(|error| err(error.to_string()))?;
    if value.as_bytes() != aaguid {
        return Err(err(format!(
            "Certificate extension id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4) value of \"{}\" was present but not equal to attestation statement AAGUID value of \"{}\"",
            crate::util::hex(value.as_bytes()),
            crate::util::hex(aaguid)
        )));
    }
    Ok(())
}

/// `mapX509SignatureAlgToCOSEAlg(oid)`.
fn signature_alg_to_cose(oid: &str) -> Result<f64, WebAuthnError> {
    Ok(match oid {
        "1.2.840.10045.4.3.2" => -7.0,
        "1.2.840.10045.4.3.3" => -35.0,
        "1.2.840.10045.4.3.4" => -36.0,
        "1.2.840.113549.1.1.11" => -257.0,
        "1.2.840.113549.1.1.12" => -258.0,
        "1.2.840.113549.1.1.13" => -259.0,
        "1.2.840.113549.1.1.5" => -65535.0,
        other => {
            return Err(err(format!(
                "Unable to map X.509 signature algorithm {other} to a COSE algorithm"
            )));
        }
    })
}

/// The modulus and exponent of a DER `RSAPublicKey`.
fn rsa_parts(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), WebAuthnError> {
    #[derive(der::Sequence)]
    struct RsaPublicKey<'a> {
        modulus: der::asn1::UintRef<'a>,
        public_exponent: der::asn1::UintRef<'a>,
    }
    let key = RsaPublicKey::from_der(der).map_err(|error| err(error.to_string()))?;
    Ok((
        key.modulus.as_bytes().to_vec(),
        key.public_exponent.as_bytes().to_vec(),
    ))
}

/// `convertX509PublicKeyToCOSE(der)`: the leaf's public key as a COSE key whose `alg` is the certificate's own
/// signature algorithm.
pub fn public_key_to_cose(certificate: &Certificate) -> Result<Cbor, WebAuthnError> {
    let tbs = &certificate.tbs_certificate;
    let spki = &tbs.subject_public_key_info;
    let alg = signature_alg_to_cose(&tbs.signature.oid.to_string());
    match spki.algorithm.oid.to_string().as_str() {
        "1.2.840.10045.2.1" => {
            let parameters = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| err("Certificate public key was missing parameters (EC2)"))?;
            let curve = parameters
                .decode_as::<ObjectIdentifier>()
                .map_err(|error| err(error.to_string()))?;
            let crv = match curve.to_string().as_str() {
                "1.2.840.10045.3.1.7" => 1.0,
                "1.3.132.0.34" => 2.0,
                other => {
                    return Err(err(format!(
                        "Certificate public key contained unexpected namedCurve {other} (EC2)"
                    )));
                }
            };
            let point = spki.subject_public_key.raw_bytes();
            if point.first() != Some(&0x04) {
                return Err(err(
                    "TODO: Figure out how to handle public keys in \"compressed form\"",
                ));
            }
            let half = (point.len() - 1) / 2;
            let x = point[1..1 + half].to_vec();
            let y = point[1 + half..].to_vec();
            Ok(Cbor::Map(vec![
                (Cbor::Number(1.0), Cbor::Number(2.0)),
                (Cbor::Number(3.0), Cbor::Number(alg?)),
                (Cbor::Number(-1.0), Cbor::Number(crv)),
                (Cbor::Number(-2.0), Cbor::Bytes(x)),
                (Cbor::Number(-3.0), Cbor::Bytes(y)),
            ]))
        }
        "1.2.840.113549.1.1.1" => {
            let (n, e) = rsa_parts(spki.subject_public_key.raw_bytes())?;
            Ok(Cbor::Map(vec![
                (Cbor::Number(1.0), Cbor::Number(3.0)),
                (Cbor::Number(3.0), Cbor::Number(alg?)),
                (Cbor::Number(-1.0), Cbor::Bytes(n)),
                (Cbor::Number(-2.0), Cbor::Bytes(e)),
            ]))
        }
        other => Err(err(format!(
            "Certificate public key contained unexpected algorithm ID {other}"
        ))),
    }
}

/// `verifySignature({ signature, data, x509Certificate, hashAlgorithm })`.
pub fn verify_with_certificate(
    der: &[u8],
    signature: &[u8],
    data: &[u8],
    hash_override: Option<f64>,
) -> Result<bool, WebAuthnError> {
    let certificate = parse(der)?;
    let key = public_key_to_cose(&certificate)?;
    cose::verify(&key, signature, data, hash_override)
}

/// Verifies `child`'s signature with `issuer`'s public key (`cert.verify({ publicKey, signatureOnly: true })`).
fn signed_by(child: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = child.tbs_certificate.to_der() else {
        return false;
    };
    let signature = child.signature.raw_bytes();
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let algorithm = child.signature_algorithm.oid.to_string();
    let hash = match algorithm.as_str() {
        "1.2.840.10045.4.3.2" | "1.2.840.113549.1.1.11" => Hash::Sha256,
        "1.2.840.10045.4.3.3" | "1.2.840.113549.1.1.12" => Hash::Sha384,
        "1.2.840.10045.4.3.4" | "1.2.840.113549.1.1.13" => Hash::Sha512,
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => Hash::Sha1,
        _ => return false,
    };
    match spki.algorithm.oid.to_string().as_str() {
        "1.2.840.10045.2.1" => {
            let Some(curve) = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
            else {
                return false;
            };
            let point = spki.subject_public_key.raw_bytes();
            let digest = hash.digest(&tbs);
            match curve.to_string().as_str() {
                "1.2.840.10045.3.1.7" => {
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Ok(key), Ok(signature)) = (
                        p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
                        p256::ecdsa::Signature::from_der(signature),
                    ) else {
                        return false;
                    };
                    key.verify_prehash(&pad(digest, 32), &signature).is_ok()
                }
                "1.3.132.0.34" => {
                    use p384::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Ok(key), Ok(signature)) = (
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(point),
                        p384::ecdsa::Signature::from_der(signature),
                    ) else {
                        return false;
                    };
                    key.verify_prehash(&pad(digest, 48), &signature).is_ok()
                }
                "1.3.132.0.35" => {
                    use p521::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Ok(key), Ok(signature)) = (
                        p521::ecdsa::VerifyingKey::from_sec1_bytes(point),
                        p521::ecdsa::Signature::from_der(signature),
                    ) else {
                        return false;
                    };
                    key.verify_prehash(&pad(digest, 66), &signature).is_ok()
                }
                _ => false,
            }
        }
        "1.2.840.113549.1.1.1" => {
            let Ok((n, e)) = rsa_parts(spki.subject_public_key.raw_bytes()) else {
                return false;
            };
            if algorithm.starts_with("1.2.840.10045") {
                return false;
            }
            cose::verify_rsa_raw(&n, &e, false, hash, 0, signature, &tbs).unwrap_or(false)
        }
        _ => false,
    }
}

fn pad(digest: Vec<u8>, field: usize) -> Vec<u8> {
    if digest.len() >= field {
        return digest;
    }
    let mut out = vec![0u8; field - digest.len()];
    out.extend(digest);
    out
}

fn self_signed(certificate: &Certificate) -> bool {
    name_key(&certificate.tbs_certificate.subject) == name_key(&certificate.tbs_certificate.issuer)
        && signed_by(certificate, certificate)
}

fn key_identifier(certificate: &Certificate) -> Option<Vec<u8>> {
    if let Some(extension) = extension(certificate, "2.5.29.35")
        && let Ok(aki) = AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes())
        && let Some(key) = aki.key_identifier
    {
        return Some(key.as_bytes().to_vec());
    }
    let extension = extension(certificate, "2.5.29.14")?;
    SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes())
        .ok()
        .map(|ski| ski.0.as_bytes().to_vec())
}

fn subject_key_identifier(certificate: &Certificate) -> Option<Vec<u8>> {
    let extension = extension(certificate, "2.5.29.14")?;
    SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes())
        .ok()
        .map(|ski| ski.0.as_bytes().to_vec())
}

fn authority_key_identifier(certificate: &Certificate) -> Option<Option<Vec<u8>>> {
    let extension = extension(certificate, "2.5.29.35")?;
    let aki = AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes()).ok()?;
    Some(aki.key_identifier.map(|key| key.as_bytes().to_vec()))
}

/// `X509ChainBuilder.findIssuer`.
fn find_issuer<'a>(certificate: &Certificate, pool: &'a [Certificate]) -> Option<&'a Certificate> {
    if self_signed(certificate) {
        return None;
    }
    let issuer = name_key(&certificate.tbs_certificate.issuer);
    let aki = authority_key_identifier(certificate);
    pool.iter().find(|candidate| {
        if name_key(&candidate.tbs_certificate.subject) != issuer {
            return false;
        }
        if let Some(Some(key)) = &aki
            && let Some(ski) = subject_key_identifier(candidate)
            && &ski != key
        {
            return false;
        }
        signed_by(certificate, candidate)
    })
}

/// `X509ChainBuilder.build(leaf)`.
fn build_chain(
    leaf: &Certificate,
    pool: &[Certificate],
) -> Result<Vec<Certificate>, WebAuthnError> {
    let mut chain = vec![leaf.clone()];
    let mut current = leaf.clone();
    while let Some(issuer) = find_issuer(&current, pool) {
        let thumbprint = issuer.to_der().map_err(|error| err(error.to_string()))?;
        for item in &chain {
            if item.to_der().map_err(|error| err(error.to_string()))? == thumbprint {
                return Err(err(
                    "Cannot build a certificate chain. Circular dependency.",
                ));
            }
        }
        chain.push(issuer.clone());
        current = issuer.clone();
    }
    Ok(chain)
}

/// The revocation lists fetched so far, keyed by issuing key identifier (`cacheRevokedCerts`).
struct CachedCrl {
    revoked: Vec<Vec<u8>>,
    next_update_ms: Option<f64>,
}

static REVOKED: LazyLock<Mutex<HashMap<Vec<u8>, CachedCrl>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> f64 {
    better_iam_core::js::now_ms()
}

/// `isCertRevoked(cert)`: pulls the certificate's CRL (first distribution point) and checks its serial number.
/// Unreachable or malformed lists count as not revoked.
async fn is_revoked(certificate: &Certificate) -> bool {
    if certificate.tbs_certificate.extensions.is_none() {
        return false;
    }
    let serial = certificate
        .tbs_certificate
        .serial_number
        .as_bytes()
        .to_vec();
    let key = key_identifier(certificate);
    if let Some(key) = &key {
        let cache = REVOKED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = cache.get(key)
            && cached.next_update_ms.is_none_or(|next| next > now_ms())
        {
            return cached.revoked.contains(&serial);
        }
    }
    let url = extension(certificate, "2.5.29.31")
        .and_then(|extension| CrlDistributionPoints::from_der(extension.extn_value.as_bytes()).ok())
        .and_then(|points| points.0.into_iter().next())
        .and_then(|point| point.distribution_point)
        .and_then(|name| match name {
            DistributionPointName::FullName(names) => names.into_iter().next(),
            DistributionPointName::NameRelativeToCRLIssuer(_) => None,
        })
        .and_then(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
            _ => None,
        });
    let Some(url) = url else {
        return false;
    };
    let fetched = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        crate::safe_fetch::plain_fetch(&url, &[]),
    )
    .await;
    let Ok(Ok((_, bytes))) = fetched else {
        return false;
    };
    let Ok(list) = CertificateList::from_der(&bytes) else {
        return false;
    };
    let next_update_ms = list.tbs_cert_list.next_update.as_ref().map(time_ms);
    let revoked: Vec<Vec<u8>> = list
        .tbs_cert_list
        .revoked_certificates
        .as_ref()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| entry.serial_number.as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default();
    let found = revoked.contains(&serial);
    if let Some(key) = key {
        REVOKED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key,
                CachedCrl {
                    revoked,
                    next_update_ms,
                },
            );
    }
    found
}

fn within_validity(certificate: &Certificate) -> bool {
    let now = now_ms();
    let validity = &certificate.tbs_certificate.validity;
    !(time_ms(&validity.not_before) > now || time_ms(&validity.not_after) < now)
}

/// `validateCertificatePath(x5c, trustAnchors)`: with no trust anchors there is nothing to chain to and the path is
/// accepted; otherwise every x5c certificate must be unrevoked and within its validity, and the leaf must chain
/// through the rest of x5c to one valid anchor.
pub async fn validate_certificate_path(
    x5c: &[Vec<u8>],
    anchors: &[Vec<u8>],
) -> Result<(), WebAuthnError> {
    if anchors.is_empty() {
        return Ok(());
    }
    let parsed: Vec<Certificate> = x5c.iter().map(|der| parse(der)).collect::<Result<_, _>>()?;
    for certificate in &parsed {
        if is_revoked(certificate).await {
            return Err(err("Found revoked certificate in x5c"));
        }
        if !within_validity(certificate) {
            return Err(err("Found certificate out of validity period in x5c"));
        }
    }
    let mut valid_anchors = Vec::new();
    for der in anchors {
        let anchor = parse(der).map_err(|_| err("Could not parse trust anchor certificate"))?;
        if is_revoked(&anchor).await || !within_validity(&anchor) {
            continue;
        }
        valid_anchors.push(anchor);
    }
    if valid_anchors.is_empty() {
        return Err(err("No specified trust anchor was valid for verifying x5c"));
    }
    let Some(leaf) = parsed.first() else {
        return Err(err("Unexpected error while validating certificate path"));
    };
    for anchor in &valid_anchors {
        let mut all: Vec<Vec<u8>> = x5c.to_vec();
        all.push(anchor.to_der().map_err(|error| err(error.to_string()))?);
        let mut unique = all.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != all.len() {
            return Err(err("Unexpected error while validating certificate path"));
        }
        let mut pool: Vec<Certificate> = parsed[1..].to_vec();
        pool.push(anchor.clone());
        let chain = build_chain(leaf, &pool)
            .map_err(|_| err("Unexpected error while validating certificate path"))?;
        if chain.len() < unique.len() {
            continue;
        }
        let last = chain
            .last()
            .map(|certificate| name_key(&certificate.tbs_certificate.subject));
        if last.as_deref() != Some(name_key(&anchor.tbs_certificate.subject).as_str()) {
            continue;
        }
        return Ok(());
    }
    Err(err(
        "x5c could not be chained to any specified trust anchor",
    ))
}

/// A directory name as relative distinguished names of (OID, text) pairs.
pub type DirectoryName = Vec<Vec<(String, String)>>;

/// The first `directoryName` of the subject alternative names, as RDNs of (OID, text) pairs.
pub fn san_directory_name(
    certificate: &Certificate,
) -> Result<Option<DirectoryName>, WebAuthnError> {
    let Some(extension) = extension(certificate, "2.5.29.17") else {
        return Ok(None);
    };
    let names = x509_cert::ext::pkix::SubjectAltName::from_der(extension.extn_value.as_bytes())
        .map_err(|error| err(error.to_string()))?;
    let first = names.0.into_iter().next();
    Ok(Some(match first {
        Some(GeneralName::DirectoryName(name)) => name
            .0
            .iter()
            .map(|rdn| {
                rdn.0
                    .iter()
                    .map(|attribute| {
                        (
                            attribute.oid.to_string(),
                            attribute_text(&AnyRef::from(&attribute.value)),
                        )
                    })
                    .collect()
            })
            .collect(),
        _ => Vec::new(),
    }))
}

/// The OIDs of the extended key usage extension, if present.
pub fn extended_key_usage(certificate: &Certificate) -> Result<Option<Vec<String>>, WebAuthnError> {
    let Some(extension) = extension(certificate, "2.5.29.37") else {
        return Ok(None);
    };
    let usage = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
        .map_err(|error| err(error.to_string()))?;
    Ok(Some(usage.0.iter().map(ToString::to_string).collect()))
}

/// The DER of every certificate in a base64 list (default trust anchors).
pub fn decode_anchors(list: &[&str]) -> Vec<Vec<u8>> {
    list.iter()
        .map(|text| crate::util::node_base64_decode(text))
        .collect()
}
