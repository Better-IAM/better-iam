//! Attestation statement formats (`registration/verifications/*` of `@simplewebauthn/server`): `packed`,
//! `fido-u2f`, `android-safetynet`, `android-key`, `tpm` and `apple`. The metadata service is not configured in
//! the TypeScript server, so no metadata statements are consulted, exactly as there.

use serde_json::Value;

use super::WebAuthnError;
use super::cbor::Cbor;
use super::cose::{self, is_cose_alg, to_hash};
use super::roots;
use super::x509;
use crate::util::{base64_padded, node_base64_decode};

fn err(message: impl Into<String>) -> WebAuthnError {
    WebAuthnError(message.into())
}

/// What every format's verifier receives.
pub struct VerifierInput<'a> {
    pub aaguid: &'a [u8],
    pub att_stmt: &'a Cbor,
    pub auth_data: &'a [u8],
    pub client_data_hash: &'a [u8],
    pub credential_id: &'a [u8],
    pub credential_public_key: &'a [u8],
    pub root_certificates: Vec<Vec<u8>>,
    pub rp_id_hash: &'a [u8],
    pub safety_net_enforce_cts_check: bool,
}

/// `SettingsService.getRootCertificates({ identifier: fmt })`: the default anchors.
pub fn root_certificates(fmt: Option<&str>) -> Vec<Vec<u8>> {
    match fmt {
        Some("android-key") => x509::decode_anchors(&[
            roots::GOOGLE_HARDWARE_ATTESTATION_ROOT_1,
            roots::GOOGLE_HARDWARE_ATTESTATION_ROOT_2,
            roots::GOOGLE_HARDWARE_ATTESTATION_ROOT_3,
            roots::GOOGLE_HARDWARE_ATTESTATION_ROOT_4,
        ]),
        Some("android-safetynet") => x509::decode_anchors(&[roots::GLOBALSIGN_ROOT_CA]),
        Some("apple") => x509::decode_anchors(&[roots::APPLE_WEBAUTHN_ROOT_CA]),
        _ => Vec::new(),
    }
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

/// The `x5c` member as DER certificates: an array of byte strings.
fn x5c_list(value: Option<&Cbor>) -> Result<Option<Vec<Vec<u8>>>, WebAuthnError> {
    match value {
        None | Some(Cbor::Null | Cbor::Undefined) => Ok(None),
        Some(Cbor::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| err("Certificate in x5c was not a byte string"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(other) if other.truthy() => Err(err("x5c was not an array of certificates")),
        Some(_) => Ok(None),
    }
}

fn wall_clock() -> f64 {
    better_iam_core::js::now_ms()
}

/// `verifyAttestationPacked`.
pub async fn packed(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let sig = input
        .att_stmt
        .get_str("sig")
        .filter(|sig| sig.truthy())
        .ok_or_else(|| {
            err("No attestation signature provided in attestation statement (Packed)")
        })?;
    let x5c = x5c_list(input.att_stmt.get_str("x5c"))?;
    let alg = input
        .att_stmt
        .get_str("alg")
        .filter(|alg| alg.truthy())
        .ok_or_else(|| err("Attestation statement did not contain alg (Packed)"))?;
    if !is_cose_alg(Some(alg)) {
        return Err(err("Attestation statement contained invalid alg (Packed)"));
    }
    let alg = alg.as_number().unwrap_or(f64::NAN);
    let sig = sig
        .as_bytes()
        .ok_or_else(|| err("Attestation signature was not a byte string (Packed)"))?;
    let signature_base = concat(&[input.auth_data, input.client_data_hash]);
    if let Some(x5c) = x5c {
        let leaf = x5c
            .first()
            .ok_or_else(|| err("No certificates present in x5c (Packed|Full)"))?;
        let info = x509::certificate_info(leaf)?;
        if info.subject.ou.as_deref() != Some("Authenticator Attestation") {
            return Err(err(
                "Certificate OU was not \"Authenticator Attestation\" (Packed|Full)",
            ));
        }
        if info.subject.cn.as_deref().is_none_or(str::is_empty) {
            return Err(err("Certificate CN was empty (Packed|Full)"));
        }
        if info.subject.o.as_deref().is_none_or(str::is_empty) {
            return Err(err("Certificate O was empty (Packed|Full)"));
        }
        if info
            .subject
            .c
            .as_deref()
            .is_none_or(|c| c.encode_utf16().count() != 2)
        {
            return Err(err(
                "Certificate C was not two-character ISO 3166 code (Packed|Full)",
            ));
        }
        if info.basic_constraints_ca {
            return Err(err(
                "Certificate basic constraints CA was not `false` (Packed|Full)",
            ));
        }
        if info.version != 2 {
            return Err(err(
                "Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)",
            ));
        }
        if info.not_before_ms > wall_clock() {
            return Err(err("Certificate not good before (Packed|Full)"));
        }
        if info.not_after_ms < wall_clock() {
            return Err(err("Certificate not good after (Packed|Full)"));
        }
        x509::validate_fido_aaguid(&info.certificate, input.aaguid)
            .map_err(|error| err(format!("{} (Packed|Full)", error.0)))?;
        x509::validate_certificate_path(&x5c, &input.root_certificates)
            .await
            .map_err(|error| err(format!("{} (Packed|Full)", error.0)))?;
        return x509::verify_with_certificate(leaf, sig, &signature_base, Some(alg));
    }
    let key = cose::decode_public_key(input.credential_public_key)?;
    cose::verify(&key, sig, &signature_base, Some(alg))
}

/// `verifyAttestationFIDOU2F`.
pub async fn fido_u2f(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let public_key = cose::cose_to_pkcs(input.credential_public_key)?;
    let signature_base = concat(&[
        &[0x00],
        input.rp_id_hash,
        input.client_data_hash,
        input.credential_id,
        &public_key,
    ]);
    let x5c = x5c_list(input.att_stmt.get_str("x5c"))?.ok_or_else(|| {
        err("No attestation certificate provided in attestation statement (FIDOU2F)")
    })?;
    let sig = input
        .att_stmt
        .get_str("sig")
        .filter(|sig| sig.truthy())
        .ok_or_else(|| {
            err("No attestation signature provided in attestation statement (FIDOU2F)")
        })?;
    // `Number.parseInt(hex(aaguid), 16) !== 0`: an all-zero (or empty, NaN) AAGUID.
    if input.aaguid.is_empty() || input.aaguid.iter().any(|byte| *byte != 0) {
        return Err(err("AAGUID was not expected value"));
    }
    x509::validate_certificate_path(&x5c, &input.root_certificates)
        .await
        .map_err(|error| err(format!("{} (FIDOU2F)", error.0)))?;
    let leaf = x5c
        .first()
        .ok_or_else(|| err("No certificates present in x5c (FIDOU2F)"))?;
    let sig = sig
        .as_bytes()
        .ok_or_else(|| err("Attestation signature was not a byte string (FIDOU2F)"))?;
    x509::verify_with_certificate(leaf, sig, &signature_base, Some(-7.0))
}

/// `verifyAttestationApple`.
pub async fn apple(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let x5c = x5c_list(input.att_stmt.get_str("x5c"))?.ok_or_else(|| {
        err("No attestation certificate provided in attestation statement (Apple)")
    })?;
    x509::validate_certificate_path(&x5c, &input.root_certificates)
        .await
        .map_err(|error| err(format!("{} (Apple)", error.0)))?;
    let leaf = x5c
        .first()
        .ok_or_else(|| err("No certificates present in x5c (Apple)"))?;
    let certificate = x509::parse(leaf)?;
    if certificate.tbs_certificate.extensions.is_none() {
        return Err(err("credCert missing extensions (Apple)"));
    }
    let extension = x509::extension(&certificate, "1.2.840.113635.100.8.2")
        .ok_or_else(|| err("credCert missing \"1.2.840.113635.100.8.2\" extension (Apple)"))?;
    let nonce = to_hash(&concat(&[input.auth_data, input.client_data_hash]), -7.0)?;
    // The first six bytes are the ASN.1 structure around the nonce (`30 24 a1 22 04 20`).
    let value = extension.extn_value.as_bytes();
    let extension_nonce = value.get(6..).unwrap_or_default();
    if nonce != extension_nonce {
        return Err(err("credCert nonce was not expected value (Apple)"));
    }
    let credential_key = cose::cose_to_pkcs(input.credential_public_key)?;
    if credential_key
        != certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
    {
        return Err(err(
            "Credential public key does not equal credCert public key (Apple)",
        ));
    }
    Ok(true)
}

/// A DER element header: (tag class + constructed + number, start of contents, length, end).
struct Element {
    class: u8,
    constructed: bool,
    number: u32,
    start: usize,
    end: usize,
}

fn read_element(data: &[u8], index: usize) -> Option<Element> {
    let first = *data.get(index)?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    let mut cursor = index + 1;
    if number == 0x1f {
        number = 0;
        loop {
            let byte = *data.get(cursor)?;
            cursor += 1;
            number = number.checked_mul(128)? | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let length_byte = *data.get(cursor)?;
    cursor += 1;
    let length = if length_byte < 0x80 {
        usize::from(length_byte)
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | usize::from(*data.get(cursor)?);
            cursor += 1;
        }
        length
    };
    let end = cursor.checked_add(length)?;
    if end > data.len() {
        return None;
    }
    Some(Element {
        class,
        constructed,
        number,
        start: cursor,
        end,
    })
}

/// The children of a constructed element.
fn children(data: &[u8], element: &Element) -> Option<Vec<Element>> {
    let mut out = Vec::new();
    let mut cursor = element.start;
    while cursor < element.end {
        let child = read_element(data, cursor)?;
        cursor = child.end;
        out.push(child);
    }
    Some(out)
}

/// The Android `KeyDescription` fields the verifier reads: the attestation challenge, and whether either
/// authorization list carries `allApplications [600]`.
fn key_description(der: &[u8]) -> Result<(Vec<u8>, bool, bool), WebAuthnError> {
    let invalid = || err("Could not parse the Android key description");
    let root = read_element(der, 0).ok_or_else(invalid)?;
    if !(root.class == 0 && root.constructed && root.number == 16) {
        return Err(invalid());
    }
    let fields = children(der, &root).ok_or_else(invalid)?;
    if fields.len() < 8 {
        return Err(invalid());
    }
    let challenge = &fields[4];
    if !(challenge.class == 0 && challenge.number == 4) {
        return Err(invalid());
    }
    let all_applications = |list: &Element| -> Result<bool, WebAuthnError> {
        if !(list.class == 0 && list.constructed && list.number == 16) {
            return Err(invalid());
        }
        Ok(children(der, list)
            .ok_or_else(invalid)?
            .iter()
            .any(|item| item.class == 2 && item.number == 600))
    };
    Ok((
        der[challenge.start..challenge.end].to_vec(),
        all_applications(&fields[6])?,
        all_applications(&fields[7])?,
    ))
}

/// `verifyAttestationAndroidKey`.
pub async fn android_key(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let x5c = x5c_list(input.att_stmt.get_str("x5c"))?.ok_or_else(|| {
        err("No attestation certificate provided in attestation statement (Android Key)")
    })?;
    let sig = input
        .att_stmt
        .get_str("sig")
        .filter(|sig| sig.truthy())
        .ok_or_else(|| {
            err("No attestation signature provided in attestation statement (Android Key)")
        })?;
    let alg = input
        .att_stmt
        .get_str("alg")
        .filter(|alg| alg.truthy())
        .ok_or_else(|| err("Attestation statement did not contain alg (Android Key)"))?;
    if !is_cose_alg(Some(alg)) {
        return Err(err(
            "Attestation statement contained invalid alg (Android Key)",
        ));
    }
    let leaf_der = x5c
        .first()
        .ok_or_else(|| err("No certificates present in x5c (Android Key)"))?;
    let leaf = x509::parse(leaf_der)?;
    let credential_key = cose::cose_to_pkcs(input.credential_public_key)?;
    if credential_key
        != leaf
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
    {
        return Err(err(
            "Credential public key does not equal leaf cert public key (Android Key)",
        ));
    }
    let extension = x509::extension(&leaf, "1.3.6.1.4.1.11129.2.1.17")
        .ok_or_else(|| err("Certificate did not contain extKeyStore (Android Key)"))?;
    let (challenge, software_all, tee_all) = key_description(extension.extn_value.as_bytes())?;
    if challenge != input.client_data_hash {
        return Err(err(
            "Attestation challenge was not equal to client data hash (Android Key)",
        ));
    }
    if tee_all || software_all {
        return Err(err(
            "teeEnforced contained \"allApplications [600]\" tag (Android Key)",
        ));
    }
    let (chain, root) = x5c.split_at(x5c.len() - 1);
    x509::validate_certificate_path(chain, root)
        .await
        .map_err(|error| err(format!("{} (Android Key)", error.0)))?;
    if !input.root_certificates.is_empty()
        && !input
            .root_certificates
            .iter()
            .any(|known| *known == root[0])
    {
        return Err(err(
            "x5c root certificate was not a known root certificate (Android Key)",
        ));
    }
    let sig = sig
        .as_bytes()
        .ok_or_else(|| err("Attestation signature was not a byte string (Android Key)"))?;
    x509::verify_with_certificate(
        leaf_der,
        sig,
        &concat(&[input.auth_data, input.client_data_hash]),
        alg.as_number(),
    )
}

/// `verifyAttestationAndroidSafetyNet`.
pub async fn android_safetynet(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let alg = input.att_stmt.get_str("alg").and_then(Cbor::as_number);
    let response = input.att_stmt.get_str("response");
    if !input.att_stmt.get_str("ver").is_some_and(Cbor::truthy) {
        return Err(err("No ver value in attestation (SafetyNet)"));
    }
    let response = response
        .filter(|response| response.truthy())
        .ok_or_else(|| err("No response was included in attStmt by authenticator (SafetyNet)"))?;
    let jwt = match response {
        Cbor::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => return Err(err("SafetyNet response was not a byte string")),
    };
    let parts: Vec<&str> = jwt.split('.').collect();
    let decode_json = |part: Option<&&str>| -> Result<Value, WebAuthnError> {
        let text = super::base64url_text(part.copied().unwrap_or_default());
        serde_json::from_str(&text).map_err(|error| err(error.to_string()))
    };
    let header = decode_json(parts.first())?;
    let payload = decode_json(parts.get(1))?;
    let signature = parts.get(2).copied().unwrap_or_default();
    let timestamp = payload
        .get("timestampMs")
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN);
    if timestamp > wall_clock() {
        return Err(err("Payload timestamp was later than now (SafetyNet)"));
    }
    if timestamp + 60_000.0 < wall_clock() {
        return Err(err("Payload timestamp has expired (SafetyNet)"));
    }
    let nonce = base64_padded(to_hash(
        &concat(&[input.auth_data, input.client_data_hash]),
        -7.0,
    )?);
    if payload.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
        return Err(err("Could not verify payload nonce (SafetyNet)"));
    }
    let cts = crate::util::truthy(payload.get("ctsProfileMatch"));
    if input.safety_net_enforce_cts_check && !cts {
        return Err(err("Could not verify device integrity (SafetyNet)"));
    }
    let certificates: Vec<Vec<u8>> = header
        .get("x5c")
        .and_then(Value::as_array)
        .ok_or_else(|| err("SafetyNet header did not carry x5c"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(node_base64_decode)
                .ok_or_else(|| err("Invalid x5c entry"))
        })
        .collect::<Result<_, _>>()?;
    let leaf = certificates
        .first()
        .ok_or_else(|| err("SafetyNet header x5c was empty"))?;
    let info = x509::certificate_info(leaf)?;
    if info.subject.cn.as_deref() != Some("attest.android.com") {
        return Err(err(
            "Certificate common name was not \"attest.android.com\" (SafetyNet)",
        ));
    }
    x509::validate_certificate_path(&certificates, &input.root_certificates)
        .await
        .map_err(|error| err(format!("{} (SafetyNet)", error.0)))?;
    let signature_base = format!(
        "{}.{}",
        parts.first().copied().unwrap_or_default(),
        parts.get(1).copied().unwrap_or_default()
    );
    let signature = super::hexagon_decode(signature, true);
    x509::verify_with_certificate(leaf, &signature, signature_base.as_bytes(), alg)
}

const TPM_MANUFACTURERS: [&str; 33] = [
    "id:414D4400",
    "id:414E5400",
    "id:41544D4C",
    "id:4252434D",
    "id:4353434F",
    "id:464C5953",
    "id:524F4343",
    "id:474F4F47",
    "id:48504900",
    "id:48504500",
    "id:48495349",
    "id:49424d00",
    "id:49424D00",
    "id:49465800",
    "id:494E5443",
    "id:4C454E00",
    "id:4D534654",
    "id:4E534D20",
    "id:4E545A00",
    "id:4E534700",
    "id:4E544300",
    "id:51434F4D",
    "id:534D534E",
    "id:53454345",
    "id:534E5300",
    "id:534D5343",
    "id:53544D20",
    "id:54584E00",
    "id:57454300",
    "id:5345414C",
    "id:FFFFF1D0",
    // Inherited members of the lookup object, which `TPM_MANUFACTURERS[value]` also finds.
    "constructor",
    "__proto__",
];

/// `TPM_ALG` names the verifier compares.
fn tpm_alg(value: u16) -> Option<&'static str> {
    Some(match value {
        0x0001 => "TPM_ALG_RSA",
        0x0004 => "TPM_ALG_SHA1",
        0x000b => "TPM_ALG_SHA256",
        0x000c => "TPM_ALG_SHA384",
        0x000d => "TPM_ALG_SHA512",
        0x0023 => "TPM_ALG_ECC",
        0x0000
        | 0x0005..=0x000a
        | 0x0010
        | 0x0012..=0x001d
        | 0x0020..=0x0022
        | 0x0025
        | 0x0026
        | 0x0040..=0x0044 => "TPM_ALG_OTHER",
        _ => return None,
    })
}

/// `TPM_ECC_CURVE_COSE_CRV_MAP[TPM_ECC_CURVE[id]]`.
fn tpm_curve_to_cose(value: u16) -> Option<f64> {
    match value {
        0x0003 | 0x0010 | 0x0020 => Some(1.0),
        0x0004 => Some(2.0),
        0x0005 => Some(3.0),
        _ => None,
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pointer: usize,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Result<u16, WebAuthnError> {
        let bytes = self
            .data
            .get(self.pointer..self.pointer + 2)
            .ok_or_else(|| err("Offset is outside the bounds of the DataView"))?;
        self.pointer += 2;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, WebAuthnError> {
        let bytes = self
            .data
            .get(self.pointer..self.pointer + 4)
            .ok_or_else(|| err("Offset is outside the bounds of the DataView"))?;
        self.pointer += 4;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// `data.slice(pointer, pointer += length)`: clamped to the end.
    fn slice(&mut self, length: usize) -> &'a [u8] {
        let start = self.pointer.min(self.data.len());
        let end = (self.pointer + length).min(self.data.len());
        self.pointer += length;
        &self.data[start..end]
    }
}

/// `verifyAttestationTPM`.
pub async fn tpm(input: &VerifierInput<'_>) -> Result<bool, WebAuthnError> {
    let statement = input.att_stmt;
    if statement.get_str("ver").and_then(Cbor::as_text) != Some("2.0") {
        return Err(err("Unexpected ver, expected \"2.0\" (TPM)"));
    }
    let sig = statement
        .get_str("sig")
        .filter(|sig| sig.truthy())
        .ok_or_else(|| err("No attestation signature provided in attestation statement (TPM)"))?;
    let alg = statement
        .get_str("alg")
        .filter(|alg| alg.truthy())
        .ok_or_else(|| err("Attestation statement did not contain alg (TPM)"))?;
    if !is_cose_alg(Some(alg)) {
        return Err(err("Attestation statement contained invalid alg (TPM)"));
    }
    let alg = alg.as_number().unwrap_or(f64::NAN);
    let x5c = x5c_list(statement.get_str("x5c"))?
        .ok_or_else(|| err("No attestation certificate provided in attestation statement (TPM)"))?;
    let pub_area = statement
        .get_str("pubArea")
        .filter(|value| value.truthy())
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Attestation statement did not contain pubArea (TPM)"))?;
    let cert_info = statement
        .get_str("certInfo")
        .filter(|value| value.truthy())
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Attestation statement did not contain certInfo (TPM)"))?;

    // parsePubArea
    let mut reader = Reader {
        data: pub_area,
        pointer: 0,
    };
    let kind = tpm_alg(reader.u16()?);
    let _name_alg = reader.u16()?;
    let _attributes = reader.u32()?;
    let policy_length = usize::from(reader.u16()?);
    reader.slice(policy_length);
    let cose_key = cose::decode_public_key(input.credential_public_key)?;
    let kty = cose_key.get_int(cose::KTY).and_then(Cbor::as_number);
    match kind {
        Some("TPM_ALG_RSA") => {
            let _symmetric = reader.u16()?;
            let _scheme = reader.u16()?;
            let _key_bits = reader.u16()?;
            let exponent = reader.u32()?;
            let unique_length = usize::from(reader.u16()?);
            let unique = reader.slice(unique_length);
            if kty != Some(cose::KTY_RSA) {
                return Err(err("Credential public key did not match TPM_ALG_RSA"));
            }
            let n = cose_key
                .get_int(cose::N)
                .filter(|n| n.truthy())
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| err("COSE public key missing n (TPM|RSA)"))?;
            let e = cose_key
                .get_int(cose::E)
                .filter(|e| e.truthy())
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| err("COSE public key missing e (TPM|RSA)"))?;
            if unique != n {
                return Err(err(
                    "PubArea unique is not same as credentialPublicKey (TPM|RSA)",
                ));
            }
            let expected = if exponent == 0 {
                65_537.0
            } else {
                f64::from(exponent)
            };
            let byte = |index: usize| e.get(index).map(|value| f64::from(*value));
            let sum = match byte(0) {
                Some(first) => {
                    first + byte(1).unwrap_or(0.0) * 256.0 + byte(2).unwrap_or(0.0) * 65_536.0
                }
                None => f64::NAN,
            };
            if expected != sum {
                return Err(err("Unexpected public key exp (TPM|RSA)"));
            }
        }
        Some("TPM_ALG_ECC") => {
            let _symmetric = reader.u16()?;
            let _scheme = reader.u16()?;
            let curve = reader.u16()?;
            let _kdf = reader.u16()?;
            let x_length = usize::from(reader.u16()?);
            let x = reader.slice(x_length).to_vec();
            let y_length = usize::from(reader.u16()?);
            let y = reader.slice(y_length).to_vec();
            if kty != Some(cose::KTY_EC2) {
                return Err(err("Credential public key did not match TPM_ALG_ECC"));
            }
            let crv = cose_key
                .get_int(cose::CRV)
                .filter(|crv| crv.truthy())
                .ok_or_else(|| err("COSE public key missing crv (TPM|ECC)"))?;
            let cose_x = cose_key
                .get_int(cose::X)
                .filter(|x| x.truthy())
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| err("COSE public key missing x (TPM|ECC)"))?;
            let cose_y = cose_key
                .get_int(cose::Y)
                .filter(|y| y.truthy())
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| err("COSE public key missing y (TPM|ECC)"))?;
            if concat(&[&x, &y]) != concat(&[cose_x, cose_y]) {
                return Err(err(
                    "PubArea unique is not same as public key x and y (TPM|ECC)",
                ));
            }
            if tpm_curve_to_cose(curve) != crv.as_number() {
                return Err(err(
                    "Public area key curve ID did not match public key crv (TPM|ECC)",
                ));
            }
        }
        _ => return Err(err("Unexpected type (TPM)")),
    }

    // parseCertInfo
    let mut reader = Reader {
        data: cert_info,
        pointer: 0,
    };
    let magic = reader.u32()?;
    let kind = reader.u16()?;
    let signer_length = usize::from(reader.u16()?);
    reader.slice(signer_length);
    let extra_length = usize::from(reader.u16()?);
    let extra_data = reader.slice(extra_length).to_vec();
    reader.slice(8);
    let _reset = reader.u32()?;
    let _restart = reader.u32()?;
    reader.slice(1);
    reader.slice(8);
    let name_length = usize::from(reader.u16()?);
    let attested_name = reader.slice(name_length).to_vec();
    let qualified_length = usize::from(reader.u16()?);
    reader.slice(qualified_length);
    let name_alg = attested_name
        .get(0..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| err("Offset is outside the bounds of the DataView"))?;
    if magic != 0xff54_4347 {
        return Err(err("Unexpected magic value, expected \"0xff544347\" (TPM)"));
    }
    if kind != 0x8017 {
        return Err(err(
            "Unexpected type, expected \"TPM_ST_ATTEST_CERTIFY\" (TPM)",
        ));
    }
    let name_hash_alg = match tpm_alg(name_alg) {
        Some("TPM_ALG_SHA256") => -7.0,
        Some("TPM_ALG_SHA384") => -35.0,
        Some("TPM_ALG_SHA512") => -36.0,
        _ => return Err(err("Unexpected TPM attested name alg")),
    };
    let pub_area_hash = to_hash(pub_area, name_hash_alg)?;
    if attested_name != concat(&[&attested_name[0..2], &pub_area_hash]) {
        return Err(err("Attested name comparison failed (TPM)"));
    }
    let to_be_signed_hash = to_hash(&concat(&[input.auth_data, input.client_data_hash]), alg)?;
    if extra_data != to_be_signed_hash {
        return Err(err(
            "CertInfo extra data did not equal hashed attestation (TPM)",
        ));
    }
    let leaf = x5c
        .first()
        .ok_or_else(|| err("No certificates present in x5c array (TPM)"))?;
    let info = x509::certificate_info(leaf)?;
    if info.basic_constraints_ca {
        return Err(err(
            "Certificate basic constraints CA was not `false` (TPM)",
        ));
    }
    if info.version != 2 {
        return Err(err(
            "Certificate version was not `3` (ASN.1 value of 2) (TPM)",
        ));
    }
    if !info.subject.combined.is_empty() {
        return Err(err("Certificate subject was not empty (TPM)"));
    }
    if info.not_before_ms > wall_clock() {
        return Err(err("Certificate not good before (TPM)"));
    }
    if info.not_after_ms < wall_clock() {
        return Err(err("Certificate not good after (TPM)"));
    }
    if info.certificate.tbs_certificate.extensions.is_none() {
        return Err(err("Certificate was missing extensions (TPM)"));
    }
    let directory = x509::san_directory_name(&info.certificate)?
        .ok_or_else(|| err("Certificate did not contain subjectAltName extension (TPM)"))?;
    if directory.first().is_none_or(Vec::is_empty) {
        return Err(err(
            "Certificate subjectAltName extension directoryName was empty (TPM)",
        ));
    }
    let mut manufacturer = None;
    let mut model = None;
    let mut version = None;
    for rdn in &directory {
        for (oid, value) in rdn {
            match oid.as_str() {
                "2.23.133.2.1" => manufacturer = Some(value.clone()),
                "2.23.133.2.2" => model = Some(value.clone()),
                "2.23.133.2.3" => version = Some(value.clone()),
                _ => {}
            }
        }
    }
    let (Some(manufacturer), Some(_), Some(_)) = (
        manufacturer.filter(|value| !value.is_empty()),
        model.filter(|value| !value.is_empty()),
        version.filter(|value| !value.is_empty()),
    ) else {
        return Err(err(
            "Certificate contained incomplete subjectAltName data (TPM)",
        ));
    };
    let usage = x509::extended_key_usage(&info.certificate)?
        .ok_or_else(|| err("Certificate did not contain ExtendedKeyUsage extension (TPM)"))?;
    if !TPM_MANUFACTURERS.contains(&manufacturer.as_str()) {
        return Err(err(format!(
            "Could not match TPM manufacturer \"{manufacturer}\" (TPM)"
        )));
    }
    if usage.first().map(String::as_str) != Some("2.23.133.8.3") {
        return Err(err(
            "Unexpected extKeyUsage, expected \"2.23.133.8.3\" (TPM)",
        ));
    }
    x509::validate_fido_aaguid(&info.certificate, input.aaguid)
        .map_err(|error| err(format!("{} (TPM)", error.0)))?;
    x509::validate_certificate_path(&x5c, &input.root_certificates)
        .await
        .map_err(|error| err(format!("{} (TPM)", error.0)))?;
    let sig = sig
        .as_bytes()
        .ok_or_else(|| err("Attestation signature was not a byte string (TPM)"))?;
    x509::verify_with_certificate(leaf, sig, cert_info, Some(alg))
}
