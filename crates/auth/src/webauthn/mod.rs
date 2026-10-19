//! WebAuthn ceremonies as `@simplewebauthn/server` 13 performs them for the passkey flows (Rust-only module):
//! `generateRegistrationOptions`, `generateAuthenticationOptions`, `verifyRegistrationResponse` and
//! `verifyAuthenticationResponse`, with every attestation format that library verifies (`none`, `packed`,
//! `fido-u2f`, `android-safetynet`, `android-key`, `tpm`, `apple`), on RustCrypto and `x509-cert` (no OpenSSL).
//!
//! Options are produced as the JSON the TypeScript server returns, and the verifiers accept and reject exactly the
//! responses the library does, so a passkey registered through either implementation authenticates on both.

pub mod attestation;
pub mod cbor;
pub mod cose;
pub mod roots;
pub mod x509;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::crypto::random_bytes;
use crate::util::{base64url, hex};
use cbor::{Cbor, decode_first, encode};

/// Why a ceremony failed (the TypeScript library throws an `Error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct WebAuthnError(pub String);

fn err(message: impl Into<String>) -> WebAuthnError {
    WebAuthnError(message.into())
}

/// `isoBase64URL.toBuffer(text)`: `@hexagon/base64`'s decoder, which reads unknown characters as zero bits and sizes
/// the output from the input length.
pub fn hexagon_decode(data: &str, url: bool) -> Vec<u8> {
    let units: Vec<u16> = data.encode_utf16().collect();
    let length = units.len();
    let mut size = length as f64 * 0.75;
    if units.last() == Some(&u16::from(b'=')) {
        size -= 1.0;
        if length >= 2 && units[length - 2] == u16::from(b'=') {
            size -= 1.0;
        }
    }
    let size = if size <= 0.0 { 0 } else { size as usize };
    let lookup = |index: usize| -> u32 {
        let Some(unit) = units.get(index) else {
            return 0;
        };
        match *unit as u32 {
            c @ 0x41..=0x5a => c - 0x41,
            c @ 0x61..=0x7a => c - 0x61 + 26,
            c @ 0x30..=0x39 => c - 0x30 + 52,
            0x2b if !url => 62,
            0x2f if !url => 63,
            0x2d if url => 62,
            0x5f if url => 63,
            _ => 0,
        }
    };
    let mut bytes = vec![0u8; size];
    let mut p = 0;
    let mut write = |value: u32, bytes: &mut Vec<u8>| {
        if p < bytes.len() {
            bytes[p] = (value & 0xff) as u8;
        }
        p += 1;
    };
    let mut i = 0;
    while i < length {
        let (e1, e2, e3, e4) = (lookup(i), lookup(i + 1), lookup(i + 2), lookup(i + 3));
        write((e1 << 2) | (e2 >> 4), &mut bytes);
        write(((e2 & 15) << 4) | (e3 >> 2), &mut bytes);
        write(((e3 & 3) << 6) | (e4 & 63), &mut bytes);
        i += 4;
    }
    bytes
}

/// `isoBase64URL.toUTF8String(text)`.
pub fn base64url_text(data: &str) -> String {
    String::from_utf8_lossy(&hexagon_decode(data, true)).into_owned()
}

/// `isoBase64URL.isBase64URL(text)`: `=` removed anywhere, then only base64url characters.
pub fn is_base64url(value: &str) -> bool {
    value
        .chars()
        .filter(|c| *c != '=')
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A credential descriptor (`excludeCredentials` / `allowCredentials` item).
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialDescriptor {
    pub id: String,
    pub transports: Option<Value>,
}

fn descriptors(list: &[CredentialDescriptor], kind: &str) -> Result<Vec<Value>, WebAuthnError> {
    list.iter()
        .map(|credential| {
            if !is_base64url(&credential.id) {
                return Err(err(format!(
                    "{kind} id \"{}\" is not a valid base64url string",
                    credential.id
                )));
            }
            let mut item = serde_json::Map::new();
            item.insert(
                "id".to_owned(),
                Value::String(credential.id.replace('=', "")),
            );
            if let Some(transports) = &credential.transports {
                item.insert("transports".to_owned(), transports.clone());
            }
            item.insert("type".to_owned(), Value::String("public-key".to_owned()));
            Ok(Value::Object(item))
        })
        .collect()
}

/// `generateChallenge()`: 32 random bytes.
pub fn generate_challenge() -> Vec<u8> {
    random_bytes(32)
}

/// The registration options the passkey flow asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationOptionsInput {
    pub rp_name: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_id: Vec<u8>,
    pub user_display_name: String,
    pub exclude_credentials: Vec<CredentialDescriptor>,
}

/// `generateRegistrationOptions({ ..., attestationType: 'none', authenticatorSelection: { residentKey: 'required',
/// userVerification: 'required' } })`.
pub fn generate_registration_options(
    input: &RegistrationOptionsInput,
    challenge: Option<Vec<u8>>,
) -> Result<Value, WebAuthnError> {
    let challenge = challenge.unwrap_or_else(generate_challenge);
    let exclude = descriptors(&input.exclude_credentials, "excludeCredential")?;
    Ok(json!({
        "challenge": base64url(&challenge),
        "rp": { "name": input.rp_name, "id": input.rp_id },
        "user": {
            "id": base64url(&input.user_id),
            "name": input.user_name,
            "displayName": input.user_display_name,
        },
        "pubKeyCredParams": [
            { "alg": -8, "type": "public-key" },
            { "alg": -7, "type": "public-key" },
            { "alg": -257, "type": "public-key" },
        ],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "required",
            "requireResidentKey": true,
        },
        "extensions": { "credProps": true },
        "hints": [],
    }))
}

/// `generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials })`.
pub fn generate_authentication_options(
    rp_id: &str,
    allow_credentials: Option<&[CredentialDescriptor]>,
    challenge: Option<Vec<u8>>,
) -> Result<Value, WebAuthnError> {
    let challenge = challenge.unwrap_or_else(generate_challenge);
    let mut options = serde_json::Map::new();
    options.insert("rpId".to_owned(), Value::String(rp_id.to_owned()));
    options.insert("challenge".to_owned(), Value::String(base64url(&challenge)));
    if let Some(list) = allow_credentials {
        options.insert(
            "allowCredentials".to_owned(),
            Value::Array(descriptors(list, "allowCredential")?),
        );
    }
    options.insert("timeout".to_owned(), json!(60000));
    options.insert(
        "userVerification".to_owned(),
        Value::String("required".to_owned()),
    );
    Ok(Value::Object(options))
}

/// The authenticator data flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    pub up: bool,
    pub uv: bool,
    pub be: bool,
    pub bs: bool,
    pub at: bool,
    pub ed: bool,
}

/// `parseAuthenticatorData(authData)`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatorData {
    pub rp_id_hash: Vec<u8>,
    pub flags: Flags,
    pub counter: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key: Option<Vec<u8>>,
    pub extensions: Option<Cbor>,
}

/// Bytes `{ 1: "OKP", 3: -8, -1: "Ed25519" }` that Firefox 117 wrote with a wrong map size.
const BAD_EDDSA_CBOR: [u8; 17] = [
    0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31,
    0x39,
];

/// `decodeAuthenticatorExtensions`: the decoded extensions must convert to an object (a map, or pairs).
fn check_extensions(value: &Cbor) -> Result<(), WebAuthnError> {
    match value {
        Cbor::Map(_) | Cbor::Text(_) => Ok(()),
        Cbor::Array(items)
            if items
                .iter()
                .all(|item| matches!(item, Cbor::Array(_) | Cbor::Text(_))) =>
        {
            Ok(())
        }
        _ => Err(err("Authenticator extensions are not a map")),
    }
}

/// `parseAuthenticatorData(authData)`.
pub fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData, WebAuthnError> {
    if data.len() < 37 {
        return Err(err(format!(
            "Authenticator data was {} bytes, expected at least 37 bytes",
            data.len()
        )));
    }
    let mut data = data.to_vec();
    let rp_id_hash = data[0..32].to_vec();
    let flags_byte = data[32];
    let flags = Flags {
        up: flags_byte & 1 != 0,
        uv: flags_byte & (1 << 2) != 0,
        be: flags_byte & (1 << 3) != 0,
        bs: flags_byte & (1 << 4) != 0,
        at: flags_byte & (1 << 6) != 0,
        ed: flags_byte & (1 << 7) != 0,
    };
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let mut pointer = 37usize;
    let slice = |data: &[u8], start: usize, end: usize| -> Vec<u8> {
        let start = start.min(data.len());
        let end = end.min(data.len()).max(start);
        data[start..end].to_vec()
    };
    let mut aaguid = None;
    let mut credential_id = None;
    let mut credential_public_key = None;
    if flags.at {
        aaguid = Some(slice(&data, pointer, pointer + 16));
        pointer += 16;
        let length = data
            .get(pointer..pointer + 2)
            .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            .ok_or_else(|| err("Offset is outside the bounds of the DataView"))?;
        pointer += 2;
        credential_id = Some(slice(&data, pointer, pointer + length));
        pointer += length;
        let found_bad =
            data.get(pointer..pointer + BAD_EDDSA_CBOR.len()) == Some(&BAD_EDDSA_CBOR[..]);
        if found_bad {
            data[pointer] = 0xa4;
        }
        let tail = slice(&data, pointer, data.len());
        let decoded = decode_first(&tail).map_err(|error| err(error.0));
        if found_bad {
            data[pointer] = 0xa3;
        }
        let encoded = encode(&decoded?);
        pointer += encoded.len();
        credential_public_key = Some(encoded);
    }
    let mut extensions = None;
    if flags.ed {
        let tail = slice(&data, pointer, data.len());
        let decoded = decode_first(&tail).map_err(|error| err(error.0))?;
        let encoded = encode(&decoded);
        let reread = decode_first(&encoded).map_err(|error| {
            err(format!(
                "Error decoding authenticator extensions: {}",
                error.0
            ))
        })?;
        check_extensions(&reread)?;
        pointer += encoded.len();
        extensions = Some(reread);
    }
    if data.len() > pointer {
        return Err(err(
            "Leftover bytes detected while parsing authenticator data",
        ));
    }
    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        counter,
        aaguid,
        credential_id,
        credential_public_key,
        extensions,
    })
}

/// `parseBackupFlags({ be, bs })`.
fn backup_flags(flags: Flags) -> Result<(&'static str, bool), WebAuthnError> {
    let device_type = if flags.be {
        "multiDevice"
    } else {
        "singleDevice"
    };
    if device_type == "singleDevice" && flags.bs {
        return Err(err(
            "Single-device credential indicated that it was backed up, which should be impossible.",
        ));
    }
    Ok((device_type, flags.bs))
}

/// `matchExpectedRPID(rpIdHash, expected)`: the RP ID whose SHA-256 (of its code units as bytes) matches.
fn match_rp_id(hash: &[u8], expected: &[String]) -> Result<String, WebAuthnError> {
    expected
        .iter()
        .find(|rp_id| {
            let bytes: Vec<u8> = rp_id
                .encode_utf16()
                .map(|unit| (unit & 0xff) as u8)
                .collect();
            Sha256::digest(&bytes).as_slice() == hash
        })
        .cloned()
        .ok_or_else(|| err("Unexpected RP ID hash"))
}

/// The JavaScript truthiness of a JSON member.
fn truthy(value: Option<&Value>) -> bool {
    crate::util::truthy(value)
}

/// `decodeClientDataJSON(data)`.
fn client_data(value: Option<&Value>) -> Result<(Value, Vec<u8>), WebAuthnError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| err("Credential response clientDataJSON was not a string"))?;
    let bytes = hexagon_decode(text, true);
    let parsed: Value = serde_json::from_str(&String::from_utf8_lossy(&bytes))
        .map_err(|error| err(error.to_string()))?;
    if parsed.is_null() {
        return Err(err("Cannot destructure client data"));
    }
    Ok((parsed, bytes))
}

/// The common checks of both ceremonies: id, type, client data type, challenge, origin.
fn check_credential(
    response: &Value,
    expected_type: &str,
    label: &str,
    expected_challenge: &str,
    expected_origins: &[String],
) -> Result<(Value, Vec<u8>), WebAuthnError> {
    if !truthy(response.get("id")) {
        return Err(err("Missing credential ID"));
    }
    if !better_iam_core::js::strict_equal(
        response.get("id").unwrap_or(&Value::Null),
        response.get("rawId").unwrap_or(&Value::Null),
    ) || response.get("rawId").is_none()
    {
        return Err(err("Credential ID was not base64url-encoded"));
    }
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err(err("Unexpected credential type, expected \"public-key\""));
    }
    let inner = response
        .get("response")
        .filter(|inner| !inner.is_null())
        .ok_or_else(|| err("Credential missing response"))?;
    let (data, bytes) = client_data(inner.get("clientDataJSON"))?;
    if data.get("type").and_then(Value::as_str) != Some(expected_type) {
        return Err(err(format!("Unexpected {label} response type")));
    }
    if data.get("challenge").and_then(Value::as_str) != Some(expected_challenge) {
        return Err(err(format!("Unexpected {label} response challenge")));
    }
    let origin = data.get("origin").and_then(Value::as_str);
    if !origin.is_some_and(|origin| expected_origins.iter().any(|expected| expected == origin)) {
        return Err(err(format!("Unexpected {label} response origin")));
    }
    Ok((data, bytes))
}

/// What `verifyRegistrationResponse` reports about a verified registration (`registrationInfo`).
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationInfo {
    pub fmt: String,
    pub aaguid: String,
    /// base64url of the credential ID.
    pub credential_id: String,
    /// The COSE public key, re-encoded as the library re-encodes it.
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub transports: Option<Value>,
    pub user_verified: bool,
    pub device_type: &'static str,
    pub backed_up: bool,
    pub origin: String,
    pub rp_id: String,
}

/// `{ verified, registrationInfo }`.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationVerification {
    pub verified: bool,
    pub info: Option<RegistrationInfo>,
}

/// The COSE algorithms a registration may use (`supportedCOSEAlgorithmIdentifiers`).
const SUPPORTED_ALGS: [f64; 10] = [
    -8.0, -7.0, -36.0, -37.0, -38.0, -39.0, -257.0, -258.0, -259.0, -65535.0,
];

/// `convertAAGUIDToString(aaguid)`.
fn aaguid_string(aaguid: &[u8]) -> String {
    let hex = hex(aaguid);
    let part = |start: usize, end: usize| {
        hex.get(start.min(hex.len())..end.min(hex.len()))
            .unwrap_or("")
            .to_owned()
    };
    [
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32),
    ]
    .join("-")
}

/// `verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID,
/// requireUserVerification })`.
pub async fn verify_registration_response(
    response: &Value,
    expected_challenge: &str,
    expected_origins: &[String],
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<RegistrationVerification, WebAuthnError> {
    let (client, client_bytes) = check_credential(
        response,
        "webauthn.create",
        "registration",
        expected_challenge,
        expected_origins,
    )?;
    if let Some(binding) = client
        .get("tokenBinding")
        .filter(|binding| truthy(Some(binding)))
    {
        if !binding.is_object() && !binding.is_array() {
            return Err(err("Unexpected value for TokenBinding"));
        }
        let status = binding.get("status").and_then(Value::as_str);
        if !status.is_some_and(|status| ["present", "supported", "not-supported"].contains(&status))
        {
            return Err(err("Unexpected tokenBinding.status value"));
        }
    }
    let inner = &response["response"];
    let attestation_object = hexagon_decode(
        inner
            .get("attestationObject")
            .and_then(Value::as_str)
            .ok_or_else(|| err("Missing attestationObject"))?,
        true,
    );
    let decoded = decode_first(&attestation_object).map_err(|error| err(error.0))?;
    if !matches!(decoded, Cbor::Map(_)) {
        return Err(err("decodedAttestationObject.get is not a function"));
    }
    let fmt = decoded.get_str("fmt");
    let auth_data = decoded
        .get_str("authData")
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Missing authData"))?
        .to_vec();
    let att_stmt = decoded
        .get_str("attStmt")
        .cloned()
        .unwrap_or(Cbor::Undefined);
    let parsed = parse_authenticator_data(&auth_data)?;
    let rp_id = match_rp_id(&parsed.rp_id_hash, &[expected_rp_id.to_owned()])?;
    if !parsed.flags.up {
        return Err(err("User presence was required, but user was not present"));
    }
    if require_user_verification && !parsed.flags.uv {
        return Err(err(
            "User verification was required, but user could not be verified",
        ));
    }
    let credential_id = parsed
        .credential_id
        .clone()
        .ok_or_else(|| err("No credential ID was provided by authenticator"))?;
    let public_key = parsed
        .credential_public_key
        .clone()
        .ok_or_else(|| err("No public key was provided by authenticator"))?;
    let aaguid = parsed
        .aaguid
        .clone()
        .ok_or_else(|| err("No AAGUID was present during registration"))?;
    let key = cose::decode_public_key(&public_key)?;
    let alg = key
        .get_int(cose::ALG)
        .and_then(Cbor::as_number)
        .ok_or_else(|| err("Credential public key was missing numeric alg"))?;
    if !SUPPORTED_ALGS.contains(&alg) {
        return Err(err(format!("Unexpected public key alg \"{alg}\"")));
    }
    let client_data_hash = Sha256::digest(&client_bytes).to_vec();
    let fmt_text = fmt.and_then(Cbor::as_text);
    let input = attestation::VerifierInput {
        aaguid: &aaguid,
        att_stmt: &att_stmt,
        auth_data: &auth_data,
        client_data_hash: &client_data_hash,
        credential_id: &credential_id,
        credential_public_key: &public_key,
        root_certificates: attestation::root_certificates(fmt_text),
        rp_id_hash: &parsed.rp_id_hash,
        safety_net_enforce_cts_check: true,
    };
    let verified = match fmt_text {
        Some("fido-u2f") => attestation::fido_u2f(&input).await?,
        Some("packed") => attestation::packed(&input).await?,
        Some("android-safetynet") => attestation::android_safetynet(&input).await?,
        Some("android-key") => attestation::android_key(&input).await?,
        Some("tpm") => attestation::tpm(&input).await?,
        Some("apple") => attestation::apple(&input).await?,
        Some("none") => {
            match &att_stmt {
                Cbor::Map(entries) if !entries.is_empty() => {
                    return Err(err("None attestation had unexpected attestation statement"));
                }
                Cbor::Null | Cbor::Undefined => {
                    return Err(err("Cannot read properties of attStmt"));
                }
                _ => {}
            }
            true
        }
        _ => return Err(err("Unsupported Attestation Format")),
    };
    if !verified {
        return Ok(RegistrationVerification {
            verified: false,
            info: None,
        });
    }
    let (device_type, backed_up) = backup_flags(parsed.flags)?;
    Ok(RegistrationVerification {
        verified: true,
        info: Some(RegistrationInfo {
            fmt: fmt_text.unwrap_or_default().to_owned(),
            aaguid: aaguid_string(&aaguid),
            credential_id: base64url(&credential_id),
            public_key,
            counter: parsed.counter,
            transports: inner.get("transports").cloned(),
            user_verified: parsed.flags.uv,
            device_type,
            backed_up,
            origin: client
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            rp_id,
        }),
    })
}

/// The stored credential an assertion is verified against.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub counter: f64,
}

/// What `verifyAuthenticationResponse` reports (`authenticationInfo`).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticationVerification {
    pub verified: bool,
    pub new_counter: u32,
    pub user_verified: bool,
    pub device_type: &'static str,
    pub backed_up: bool,
    pub origin: String,
    pub rp_id: String,
}

/// `verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID,
/// requireUserVerification, credential })`.
pub fn verify_authentication_response(
    response: &Value,
    expected_challenge: &str,
    expected_origins: &[String],
    expected_rp_id: &str,
    require_user_verification: bool,
    credential: &StoredCredential,
) -> Result<AuthenticationVerification, WebAuthnError> {
    let (client, client_bytes) = check_credential(
        response,
        "webauthn.get",
        "authentication",
        expected_challenge,
        expected_origins,
    )?;
    let inner = &response["response"];
    let authenticator_data = inner
        .get("authenticatorData")
        .and_then(Value::as_str)
        .filter(|data| is_base64url(data))
        .ok_or_else(|| err("Credential response authenticatorData was not a base64url string"))?;
    let signature = inner
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| is_base64url(signature))
        .ok_or_else(|| err("Credential response signature was not a base64url string"))?;
    if truthy(inner.get("userHandle")) && !inner.get("userHandle").is_some_and(Value::is_string) {
        return Err(err("Credential response userHandle was not a string"));
    }
    if let Some(binding) = client
        .get("tokenBinding")
        .filter(|binding| truthy(Some(binding)))
    {
        if !binding.is_object() && !binding.is_array() {
            return Err(err("ClientDataJSON tokenBinding was not an object"));
        }
        let status = binding.get("status").and_then(Value::as_str);
        if !status.is_some_and(|status| ["present", "supported", "notSupported"].contains(&status))
        {
            return Err(err("Unexpected tokenBinding status"));
        }
    }
    let auth_data = hexagon_decode(authenticator_data, true);
    let parsed = parse_authenticator_data(&auth_data)?;
    let rp_id = match_rp_id(&parsed.rp_id_hash, &[expected_rp_id.to_owned()])?;
    if !parsed.flags.up {
        return Err(err("User not present during authentication"));
    }
    if require_user_verification && !parsed.flags.uv {
        return Err(err(
            "User verification required, but user could not be verified",
        ));
    }
    let client_data_hash = Sha256::digest(&client_bytes);
    let mut signature_base = auth_data.clone();
    signature_base.extend_from_slice(&client_data_hash);
    let signature = hexagon_decode(signature, true);
    let counter = f64::from(parsed.counter);
    if (counter > 0.0 || credential.counter > 0.0) && counter <= credential.counter {
        return Err(err(format!(
            "Response counter value {} was lower than expected {}",
            parsed.counter, credential.counter
        )));
    }
    let (device_type, backed_up) = backup_flags(parsed.flags)?;
    let key = cose::decode_public_key(&credential.public_key)?;
    let verified = cose::verify(&key, &signature, &signature_base, None)?;
    Ok(AuthenticationVerification {
        verified,
        new_counter: parsed.counter,
        user_verified: parsed.flags.uv,
        device_type,
        backed_up,
        origin: client
            .get("origin")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        rp_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_hexagon_base64() {
        assert_eq!(hexagon_decode("AQID", true), vec![1, 2, 3]);
        assert_eq!(hexagon_decode("AQI", true), vec![1, 2]);
        assert_eq!(hexagon_decode("AQ==", false), vec![1]);
        assert!(is_base64url("ab-_=="));
        assert!(!is_base64url("ab+/"));
    }

    #[test]
    fn formats_aaguids() {
        assert_eq!(
            aaguid_string(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000"
        );
    }
}
