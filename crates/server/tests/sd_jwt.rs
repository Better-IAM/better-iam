//! SD-JWT VCs, Token Status Lists and OpenID4VCI holder proofs: ported from tests/sd-jwt.test.ts. The TypeScript
//! test signs with `node:crypto` keys and jose's `SignJWT`; here P-256 keys from `p256` sign through
//! `sd_jwt::sign_jwt`, the same compact JWS.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_server::sd_jwt::{
    Disclose, HolderProofOptions, IssueSdJwtInput, IssuedSdJwt, IssuerKeyFn, PresentOptions,
    PublicKey, STATUS_INVALID, STATUS_SUSPENDED, STATUS_VALID, SignStatusListInput, SigningKey,
    VerificationKey, VerifyFailure, VerifySdJwtOptions, issue_sd_jwt, present_sd_jwt,
    read_disclosure, read_status_list, set_status_at, sign_jwt, sign_status_list, split_sd_jwt,
    status_at, verify_holder_proof, verify_sd_jwt,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://issuer.example";

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_ms() -> f64 {
    better_iam_server::utils::date_now()
}

fn key() -> p256::ecdsa::SigningKey {
    loop {
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
            break key;
        }
    }
}

/// `exportJWK(publicKey)` reduced to `{ kty, crv, x, y }`.
fn public_jwk(key: &p256::ecdsa::SigningKey) -> Map<String, Value> {
    let point = key.verifying_key().to_encoded_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(point.x().unwrap()),
        "y": b64(point.y().unwrap()),
    });
    jwk.as_object().unwrap().clone()
}

struct Keys {
    issuer: p256::ecdsa::SigningKey,
    holder: p256::ecdsa::SigningKey,
}

impl Keys {
    fn new() -> Self {
        Keys {
            issuer: key(),
            holder: key(),
        }
    }

    /// `issuerKey(kid, issuer)`: the issuer's public key for `k1` at `https://issuer.example`.
    fn issuer_key(&self) -> IssuerKeyFn<'static> {
        let public = *self.issuer.verifying_key();
        Box::new(move |kid: String, issuer: String| {
            Box::pin(async move {
                Ok((kid == "k1" && issuer == ISSUER)
                    .then(|| VerificationKey::Key(PublicKey::P256(public))))
            })
        })
    }

    fn options(&self) -> VerifySdJwtOptions<'static> {
        VerifySdJwtOptions::new(self.issuer_key())
    }

    fn credential(&self) -> IssuedSdJwt {
        let now = (now_ms() / 1000.0).floor();
        let plain = json!({
            "iss": ISSUER,
            "vct": "https://issuer.example/types/employee",
            "iat": now,
            "exp": now + 3600.0,
            "cnf": { "jwk": public_jwk(&self.holder) },
            "status": { "status_list": { "idx": 7, "uri": "https://issuer.example/status/1" } },
        });
        let disclosable = json!({
            "email": "alice@acme.test",
            "department": "Engineering",
            "teams": ["Platform", "SRE"],
        });
        issue_sd_jwt(&IssueSdJwtInput {
            alg: "ES256",
            kid: "k1",
            key: &SigningKey::P256(self.issuer.clone()),
            typ: None,
            plain: plain.as_object().unwrap(),
            disclosable: disclosable.as_object().unwrap(),
            decoys: Some(2),
        })
        .expect("issued")
    }
}

fn reason(failure: VerifyFailure) -> String {
    match failure {
        VerifyFailure::SdJwt(error) => error.reason,
        VerifyFailure::Other(error) => panic!("expected an SdJwtError, got {error:?}"),
    }
}

fn run<F: std::future::Future<Output = ()>>(body: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(body);
}

fn decode_payload(jwt: &str) -> Value {
    let part = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[test]
fn issues_presents_selected_claims_with_key_binding_and_verifies() {
    run(async {
        let keys = Keys::new();
        let issued = keys.credential();
        let split = split_sd_jwt(&issued.sd_jwt).unwrap();
        let mut names: Vec<String> = split
            .disclosures
            .iter()
            .map(|item| read_disclosure(item).unwrap().0)
            .collect();
        names.sort();
        assert_eq!(names, ["department", "email", "teams"]);
        // The signed payload holds digests (3 claims + 2 decoys), never the values.
        let payload = decode_payload(&issued.jwt);
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 5);
        assert!(!payload.to_string().contains("alice@acme.test"));

        let holder = SigningKey::P256(keys.holder.clone());
        let presentation = present_sd_jwt(
            &issued.sd_jwt,
            &PresentOptions {
                disclose: Disclose::Names(vec!["email".into()]),
                holder_key: &holder,
                alg: "ES256",
                audience: "https://verifier.example",
                nonce: "n-123",
                issued_at: None,
            },
        )
        .unwrap();
        let mut options = keys.options();
        options.audience = Some(json!("https://verifier.example"));
        options.nonce = Some(json!("n-123"));
        let verified = verify_sd_jwt(&presentation, options).await.unwrap();
        assert_eq!(verified.issuer, ISSUER);
        assert_eq!(
            verified.vct.as_deref(),
            Some("https://issuer.example/types/employee")
        );
        assert_eq!(verified.disclosed, ["email"]);
        assert!(verified.key_bound);
        assert_eq!(
            verified.status,
            Some(json!({ "index": 7, "uri": "https://issuer.example/status/1" }))
        );
        assert_eq!(verified.claims["email"], "alice@acme.test");
        assert!(!verified.claims.contains_key("department"));
        assert!(!verified.claims.contains_key("_sd"));

        // Wrong audience or nonce, a replayed KB over another selection, a forged disclosure, no key binding.
        let mut options = keys.options();
        options.audience = Some(json!("https://other.example"));
        options.nonce = Some(json!("n-123"));
        assert_eq!(
            reason(verify_sd_jwt(&presentation, options).await.unwrap_err()),
            "wrong-audience"
        );
        let mut options = keys.options();
        options.audience = Some(json!("https://verifier.example"));
        options.nonce = Some(json!("x"));
        assert_eq!(
            reason(verify_sd_jwt(&presentation, options).await.unwrap_err()),
            "wrong-nonce"
        );
        let parts: Vec<&str> = presentation.split('~').collect();
        let (jwt, email, kb) = (parts[0], parts[1], parts[parts.len() - 1]);
        let department = split
            .disclosures
            .iter()
            .find(|item| read_disclosure(item).unwrap().0 == "department")
            .unwrap();
        let widened = format!("{jwt}~{email}~{department}~{kb}");
        assert_eq!(
            reason(verify_sd_jwt(&widened, keys.options()).await.unwrap_err()),
            "bad-key-binding"
        );
        let forged = b64(json!(["salt", "email", "mallory@evil.test"]).to_string());
        let mut options = keys.options();
        options.require_key_binding = Some(false);
        assert_eq!(
            reason(
                verify_sd_jwt(&format!("{jwt}~{forged}~"), options)
                    .await
                    .unwrap_err()
            ),
            "bad-disclosure"
        );
        assert_eq!(
            reason(
                verify_sd_jwt(&issued.sd_jwt, keys.options())
                    .await
                    .unwrap_err()
            ),
            "key-binding-required"
        );
        // A disclosure may not overwrite a signed claim.
        let iss = b64(json!(["salt", "iss", "https://evil.test"]).to_string());
        let mut options = keys.options();
        options.require_key_binding = Some(false);
        assert_eq!(
            reason(
                verify_sd_jwt(&format!("{jwt}~{iss}~"), options)
                    .await
                    .unwrap_err()
            ),
            "bad-disclosure"
        );
        // Unknown issuers and expired credentials.
        let mut options = VerifySdJwtOptions::new(Box::new(|_, _| Box::pin(async { Ok(None) })));
        options.audience = Some(json!("https://verifier.example"));
        assert_eq!(
            reason(verify_sd_jwt(&presentation, options).await.unwrap_err()),
            "unknown-issuer"
        );
        let mut options = keys.options();
        options.now = Some(now_ms() + 7_200_000.0);
        options.max_key_binding_age_seconds = Some(10_000.0);
        assert_eq!(
            reason(verify_sd_jwt(&presentation, options).await.unwrap_err()),
            "expired"
        );
        // The key-binding claims come back for the verifier's own replay bookkeeping.
        let binding = verified.key_binding.unwrap();
        assert_eq!(binding["audience"], "https://verifier.example");
        assert_eq!(binding["nonce"], "n-123");
    });
}

#[test]
fn refuses_claim_names_that_would_reach_the_prototype_or_shadow_sd_jwt_structure() {
    run(async {
        let keys = Keys::new();
        let issuer = SigningKey::P256(keys.issuer.clone());
        for name in ["__proto__", "constructor", "_sd", "...", "cnf"] {
            let mut disclosable = Map::new();
            disclosable.insert(name.to_owned(), json!("value"));
            let plain = json!({ "iss": ISSUER, "vct": "x" });
            assert!(
                issue_sd_jwt(&IssueSdJwtInput {
                    alg: "ES256",
                    kid: "k1",
                    key: &issuer,
                    typ: None,
                    plain: plain.as_object().unwrap(),
                    disclosable: &disclosable,
                    decoys: None,
                })
                .is_err(),
                "{name} must not be disclosable"
            );
        }
        let header = json!({ "alg": "ES256", "kid": "k1", "typ": "dc+sd-jwt" });
        let header = header.as_object().unwrap();
        // A disclosure named like the prototype never verifies, even if its digest were signed.
        let salt = "c2FsdA";
        let disclosure = b64(json!([salt, "__proto__", { "admin": true }]).to_string());
        let digest = b64(Sha256::digest(disclosure.as_bytes()));
        let payload = json!({ "iss": ISSUER, "vct": "x", "_sd_alg": "sha-256", "_sd": [digest] });
        let jwt = sign_jwt(header, payload.as_object().unwrap(), &issuer).unwrap();
        let mut options = keys.options();
        options.require_key_binding = Some(false);
        assert_eq!(
            reason(
                verify_sd_jwt(&format!("{jwt}~{disclosure}~"), options)
                    .await
                    .unwrap_err()
            ),
            "bad-disclosure"
        );
        // Nor does a digest listed twice.
        let email = b64(json!([salt, "email", "a@b.test"]).to_string());
        let twice = b64(Sha256::digest(email.as_bytes()));
        let payload =
            json!({ "iss": ISSUER, "vct": "x", "_sd_alg": "sha-256", "_sd": [twice, twice] });
        let doubled = sign_jwt(header, payload.as_object().unwrap(), &issuer).unwrap();
        let mut options = keys.options();
        options.require_key_binding = Some(false);
        assert_eq!(
            reason(
                verify_sd_jwt(&format!("{doubled}~{email}~"), options)
                    .await
                    .unwrap_err()
            ),
            "bad-disclosure"
        );
    });
}

#[test]
fn encodes_token_status_lists_and_holder_proofs() {
    run(async {
        let keys = Keys::new();
        let mut bytes = vec![0u8; 16];
        set_status_at(&mut bytes, 0.0, 2.0, STATUS_INVALID).unwrap();
        set_status_at(&mut bytes, 5.0, 2.0, STATUS_SUSPENDED).unwrap();
        assert_eq!(bytes[0], 0b01);
        assert_eq!(bytes[1], 0b1000);
        let issuer = SigningKey::P256(keys.issuer.clone());
        let token = sign_status_list(&SignStatusListInput {
            uri: "https://issuer.example/status/1",
            bytes: &bytes,
            bits: 2.0,
            alg: "ES256",
            kid: "k1",
            key: &issuer,
            issued_at: now_ms(),
            expires_at: now_ms() + 3_600_000.0,
            ttl_seconds: 300.0,
        })
        .unwrap();
        let public = VerificationKey::Key(PublicKey::P256(*keys.issuer.verifying_key()));
        let read = read_status_list(&token, &public, "https://issuer.example/status/1", None)
            .await
            .unwrap();
        assert_eq!(
            [
                status_at(&read.bytes, 0.0, 2.0).unwrap(),
                status_at(&read.bytes, 5.0, 2.0).unwrap(),
                status_at(&read.bytes, 6.0, 2.0).unwrap(),
            ],
            [STATUS_INVALID, STATUS_SUSPENDED, STATUS_VALID]
        );
        let other = read_status_list(&token, &public, "https://issuer.example/status/2", None)
            .await
            .unwrap_err();
        assert_eq!(other.reason, "status-unavailable");

        let holder_jwk = public_jwk(&keys.holder);
        let header = json!({ "alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": holder_jwk });
        let payload = json!({ "aud": ISSUER, "nonce": "c-1", "iat": (now_ms() / 1000.0).floor() });
        let proof = sign_jwt(
            header.as_object().unwrap(),
            payload.as_object().unwrap(),
            &SigningKey::P256(keys.holder.clone()),
        )
        .unwrap();
        let checked = verify_holder_proof(
            Some(&Value::String(proof.clone())),
            &HolderProofOptions {
                audience: ISSUER,
                now: None,
                max_age_seconds: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(checked.nonce.as_deref(), Some("c-1"));
        assert_eq!(checked.jwk, holder_jwk);
        assert_eq!(checked.thumbprint.len(), 43);
        assert!(
            checked
                .thumbprint
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        let refused = verify_holder_proof(
            Some(&Value::String(proof)),
            &HolderProofOptions {
                audience: "https://other.example",
                now: None,
                max_age_seconds: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(reason(refused), "bad-key-binding");
    });
}
