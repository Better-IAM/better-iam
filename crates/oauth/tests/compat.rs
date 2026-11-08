//! Mixed-fleet vectors produced by the TypeScript implementation: artifacts sealed by Node's AES-256-GCM `cipher`
//! open in Rust (and the reverse round trip), keygrip cookie signatures match, and PKCE / thumbprints agree.

use better_iam_oauth::jose;
use better_iam_oauth::provider::http::Keygrip;
use better_iam_oauth::{cipher, encryption_key, hash};
use serde_json::json;

#[test]
fn opens_artifacts_sealed_by_the_typescript_provider() {
    let key = encryption_key("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=").expect("key");
    let sealed = "AwMDAwMDAwMDAwMDXtzIajRMfHhYASA/jiSMWIJXhYGWubYaW7eli8GEItuTi19B95LALrrBLye37JAgRQY/5vrhUgdJChSBUVztBp6HGVSNzxVla9yGq/byvEPfkPsIUkUPgt+LYU9suQwnSNgveQ==";
    let crypt = cipher(key);
    assert_eq!(
        crypt.open(sealed).expect("opens"),
        json!({ "kind": "AccessToken", "jti": "abc", "clientId": "web", "scope": "openid", "iat": 1, "exp": 2 })
    );
    let resealed = crypt.seal(&json!({ "a": 1 }));
    assert_eq!(crypt.open(&resealed).unwrap(), json!({ "a": 1 }));
    assert!(crypt.open("AAAA").is_err());
    assert_eq!(
        encryption_key("c2hvcnQ=").unwrap_err().code,
        "configuration"
    );
}

#[test]
fn signs_cookies_as_koa_keygrip_does() {
    let keygrip = Keygrip::new(vec!["test-key-with-at-least-32-characters-long".into()]);
    assert_eq!(
        keygrip.sign("_session=abc123"),
        "lwDoOIEs9IHGiCVGUSjDxC47y_U"
    );
    let rotated = Keygrip::new(vec![
        "a-newer-key-with-at-least-32-characters".into(),
        "test-key-with-at-least-32-characters-long".into(),
    ]);
    assert_eq!(
        rotated.index("_session=abc123", "lwDoOIEs9IHGiCVGUSjDxC47y_U"),
        Some(1)
    );
}

#[test]
fn agrees_on_hashes_pkce_and_thumbprints() {
    assert_eq!(
        hash("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // RFC 7636 appendix B.
    assert_eq!(
        jose::sha256_b64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    // RFC 7638 section 3.1.
    let jwk = json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    });
    assert_eq!(
        jose::jwk_thumbprint(jwk.as_object().unwrap()).unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}
