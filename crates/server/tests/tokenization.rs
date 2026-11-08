//! The tokenization module (tokenization.ts): value normalization, token shapes, masks, fingerprints and sealing.
//! Ported from the cases of tests/protection.test.ts and tests/protection-security.test.ts that these functions decide
//! (each data type's token shape and mask, short values keeping half hidden, card styles, letters and digits of every
//! script, NFC normalization, refused control and bidirectional characters, SSN tokens outside the SSN and ITIN
//! ranges). The end-to-end protection API cases live in tests/protection.rs.

use better_iam_core::IamResult;
use better_iam_server::tokenization::{
    DEFAULT_MASK, ProtectionProfile, fingerprint, format_preserving_space, lookup_context,
    mask_style, mask_value, needs_deterministic, new_token, normalize_value, open_value,
    profile_name, protection_actions, seal_value, summarize_profile, token_key,
};
use regex::Regex;
use serde_json::{Value, json};

fn s(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn code<T: std::fmt::Debug>(result: IamResult<T>) -> String {
    result.expect_err("an error").code
}

fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    for (index, char) in digits.chars().rev().enumerate() {
        let mut digit = char.to_digit(10).unwrap();
        if index % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum % 10 == 0
}

/// A card number with a valid Luhn check digit.
fn card(prefix: &str) -> String {
    (0..10)
        .map(|check| format!("{prefix}{check}"))
        .find(|digits| luhn(digits))
        .unwrap()
}

/// Normalizes, tokenizes and masks one value as `tokenize` and `mask` do.
fn shapes(data_type: &str, format: &str, value: &str) -> (String, String) {
    let normalized = normalize_value(&s(data_type), Some(&s(value))).unwrap();
    let token = new_token(&s(data_type), &s(format), &normalized).unwrap();
    let mask = DEFAULT_MASK[data_type].clone();
    (
        token,
        mask_value(&s(data_type), &mask, &normalized).unwrap(),
    )
}

#[test]
fn tokenizes_card_numbers_into_format_preserving_tokens() {
    // tests/protection.test.ts "tokenizes card numbers into format-preserving tokens and back".
    let sixteen = Regex::new(r"^\d{16}$").unwrap();
    for value in ["4242 4242 4242 4242", "5555-5555-5555-4444"] {
        let normalized = normalize_value(&s("card"), Some(&s(value))).unwrap();
        for _ in 0..50 {
            let token = new_token(&s("card"), &s("format-preserving"), &normalized).unwrap();
            assert!(sixteen.is_match(&token));
            assert_eq!(&token[12..], &normalized[12..]);
            assert!(!luhn(&token), "a token is never a card number");
        }
    }
    assert_eq!(
        mask_value(&s("card"), &s("last4"), "5555555555554444").unwrap(),
        "************4444"
    );
    assert_eq!(
        mask_value(&s("card"), &s("first6last4"), "5555555555554444").unwrap(),
        "555555******4444"
    );
    assert_eq!(
        code(normalize_value(&s("card"), Some(&s("4242 4242 4242 4241")))),
        "INVALID_INPUT"
    );
    assert_eq!(
        code(normalize_value(&s("card"), Some(&s("12345")))),
        "INVALID_INPUT"
    );
    assert_eq!(
        normalize_value(&s("card"), Some(&json!(4242)))
            .unwrap_err()
            .message,
        "Every value must be a string"
    );
    assert_eq!(
        normalize_value(&s("card"), Some(&s("1")))
            .unwrap_err()
            .message,
        "Not a valid card number"
    );
}

#[test]
fn keeps_each_data_type_recognizable_and_masks_it_for_display() {
    // tests/protection.test.ts "keeps each data type recognizable and masks it for display".
    let cases = [
        ("ssn", "123-45-6789", r"^9\d\d-\d\d-6789$", "***-**-6789"),
        (
            "email",
            "Jane.Doe@Example.com",
            r"^[a-z0-9]{16}@example\.com$",
            "j***@example.com",
        ),
        (
            "phone",
            "+1 (415) 555-0199",
            r"^\+\d{7}0199$",
            "+*******0199",
        ),
    ];
    for (data_type, value, shape, masked) in cases {
        let (token, mask) = shapes(data_type, "format-preserving", value);
        assert!(
            Regex::new(shape).unwrap().is_match(&token),
            "{data_type}: {token}"
        );
        assert_eq!(mask, masked);
    }
    let (token, mask) = shapes("generic", "random", "patient allergic to penicillin");
    assert!(
        Regex::new(r"^tok_[0-9A-Za-z]{22}$")
            .unwrap()
            .is_match(&token)
    );
    assert_eq!(mask, "******* ******** ** **********");
    // Format-preserving generic tokens keep each character's class.
    let (account, _) = shapes(
        "generic",
        "format-preserving",
        "DE89-3704-0044-0532-0130-00",
    );
    assert!(
        Regex::new(r"^[A-Z]{2}\d{2}-\d{4}-\d{4}-\d{4}-\d{4}-\d{2}$")
            .unwrap()
            .is_match(&account)
    );
    assert!(format_preserving_space(&s("generic"), "DE89-3704-0044-0532-0130-00").unwrap());
    assert!(!format_preserving_space(&s("generic"), "AB-12").unwrap());
    assert!(format_preserving_space(&s("card"), "4242").unwrap());
    // Equal SSNs normalize alike, so deterministic profiles give them one token.
    assert_eq!(
        normalize_value(&s("ssn"), Some(&s("123456789"))).unwrap(),
        normalize_value(&s("ssn"), Some(&s("123-45-6789"))).unwrap()
    );
}

#[test]
fn never_lets_a_mask_reveal_most_of_a_value() {
    // tests/protection-security.test.ts "never lets a mask reveal most of a value, and decides the style actually used".
    assert_eq!(
        code(mask_style(
            &s("ssn"),
            Some(&s("first6last4")),
            Some("style")
        )),
        "INVALID_INPUT"
    );
    assert_eq!(
        mask_style(&s("card"), Some(&s("email")), None)
            .unwrap_err()
            .message,
        "mask must be one of last4, first6last4, full for card values"
    );
    assert_eq!(
        mask_style(&s("card"), Some(&s("first6last4")), None).unwrap(),
        s("first6last4")
    );
    // Short values keep at least half hidden.
    let phone = normalize_value(&s("phone"), Some(&s("555-0199"))).unwrap();
    assert_eq!(
        mask_value(&s("phone"), &s("last4"), &phone).unwrap(),
        "****199"
    );
    // Six and four digits of a card only when at least five stay hidden (15 digits or more).
    let short = card("42424242424");
    let long = card("424242424242424");
    assert_eq!(
        mask_value(&s("card"), &s("first6last4"), &short).unwrap(),
        format!("********{}", &short[8..])
    );
    assert_eq!(
        mask_value(&s("card"), &s("first6last4"), &long).unwrap(),
        format!("424242******{}", &long[12..])
    );
    // An email with a short local part hides its first character too.
    assert_eq!(
        mask_value(&s("email"), &s("email"), "bob@acme.test").unwrap(),
        "****@acme.test"
    );
    assert_eq!(
        mask_value(&s("email"), &s("email"), "@x.y").unwrap(),
        "@*.*"
    );
}

#[test]
fn hides_and_replaces_letters_and_digits_of_every_script() {
    // tests/protection-security.test.ts "hides and replaces letters and digits of every script".
    let names = "Иван Петров, José García, 山田太郎";
    let masked = mask_value(&s("generic"), &s("full"), names).unwrap();
    assert!(!Regex::new(r"[\p{L}\p{N}]").unwrap().is_match(&masked));
    assert_eq!(masked.chars().count(), names.chars().count());

    let preserved = new_token(
        &s("generic"),
        &s("format-preserving"),
        "Иван Петров ACCT-1234-5678",
    )
    .unwrap();
    assert!(
        Regex::new(r"^[A-Z][a-z]{3} [A-Z][a-z]{5} [A-Z]{4}-\d{4}-\d{4}$")
            .unwrap()
            .is_match(&preserved)
    );
    let arabic = new_token(&s("generic"), &s("format-preserving"), "١٢٣٤٥٦٧٨٩٠١٢").unwrap();
    assert!(Regex::new(r"^\d{12}$").unwrap().is_match(&arabic));
    // Long format-preserving values have short unique keys.
    let long = "Ab1-".repeat(200);
    let token = new_token(&s("generic"), &s("format-preserving"), &long).unwrap();
    assert_eq!(token.chars().count(), long.chars().count());
    let key = token_key("p1", &token).unwrap();
    assert!(key.starts_with("token:p1:") && key.len() == "token:p1:".len() + 43);
}

#[test]
fn normalizes_text_and_refuses_what_cannot_be_shown_faithfully() {
    // tests/protection-security.test.ts "normalizes text so equal values share a token, and refuses what cannot be
    // shown faithfully". (Unpaired surrogates cannot reach Rust: the JSON decoder refuses them.)
    assert_eq!(
        normalize_value(&s("generic"), Some(&s("jos\u{e9} garcia"))).unwrap(),
        normalize_value(&s("generic"), Some(&s("jose\u{301} garcia"))).unwrap()
    );
    for value in ["abc\u{7f}def", "pay\u{85}", "\u{202e}evil", ""] {
        assert_eq!(
            normalize_value(&s("generic"), Some(&s(value)))
                .unwrap_err()
                .message,
            "Values are 1 to 4096 characters of well-formed text without control or bidirectional formatting characters"
        );
    }
    assert_eq!(
        normalize_value(&s("generic"), Some(&s("tab\tand\nnewline"))).unwrap(),
        "tab\tand\nnewline"
    );
    assert_eq!(
        code(normalize_value(&s("email"), Some(&s("a\u{1}b@acme.test")))),
        "INVALID_INPUT"
    );
    assert_eq!(
        normalize_value(&s("email"), Some(&s("  Bob@ACME.test "))).unwrap(),
        "bob@acme.test"
    );
    for email in [
        "bob@acme",
        "bob@acme..test",
        "b<o>b@acme.test",
        "@acme.test",
        "bob@acme_test.io",
    ] {
        assert_eq!(
            normalize_value(&s("email"), Some(&s(email)))
                .unwrap_err()
                .message,
            "Not a valid email address"
        );
    }
    assert_eq!(
        normalize_value(&s("phone"), Some(&s("+1.415.555.0199"))).unwrap(),
        "+14155550199"
    );
    assert_eq!(
        code(normalize_value(&s("phone"), Some(&s("12345")))),
        "INVALID_INPUT"
    );
    assert_eq!(
        code(normalize_value(&s("ssn"), Some(&s("12-345-678")))),
        "INVALID_INPUT"
    );
}

#[test]
fn keeps_short_format_preserving_tokens_from_matching_real_numbers() {
    // tests/protection-security.test.ts "keeps short format-preserving tokens from running out or matching real
    // numbers".
    assert!(needs_deterministic(&s("ssn"), &s("format-preserving")).unwrap());
    assert!(needs_deterministic(&s("phone"), &s("format-preserving")).unwrap());
    assert!(!needs_deterministic(&s("ssn"), &s("random")).unwrap());
    assert!(!needs_deterministic(&s("card"), &s("format-preserving")).unwrap());
    let shape = Regex::new(r"^9\d\d-\d\d-\d{4}$").unwrap();
    for index in 0..100 {
        let value = format!("123-45-{index:04}");
        let token = new_token(&s("ssn"), &s("format-preserving"), &value).unwrap();
        assert!(shape.is_match(&token));
        let group: u32 = token[4..6].parse().unwrap();
        assert!(
            !((50..=65).contains(&group)
                || (70..=88).contains(&group)
                || (90..=92).contains(&group)
                || (94..=99).contains(&group)
                || group == 0),
            "group {group} of {token}"
        );
        assert_eq!(&token[7..], &value[7..]);
    }
}

#[test]
fn seals_fingerprints_and_names() {
    let key = vec![7u8; 32];
    let sealed = seal_value(&key, "t1", "p1", "tok_x", "4242424242424242").unwrap();
    let record = json!({ "tenantId": "t1", "profileId": "p1", "token": "tok_x", "sealed": sealed });
    assert_eq!(open_value(&key, &record).unwrap(), "4242424242424242");
    let other = json!({ "tenantId": "t2", "profileId": "p1", "token": "tok_x", "sealed": sealed });
    let error = open_value(&key, &other).unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status, error.message.as_str()),
        (
            "KEY_MATERIAL_UNAVAILABLE",
            500,
            "A stored value cannot be opened"
        )
    );
    assert_eq!(
        open_value(&[1u8; 32], &record).unwrap_err().code,
        "KEY_MATERIAL_UNAVAILABLE"
    );
    assert_eq!(
        open_value(&key, &json!({ "sealed": "short" }))
            .unwrap_err()
            .code,
        "KEY_MATERIAL_UNAVAILABLE"
    );

    // HMAC-SHA256, base64url: the same key and value give the same fingerprint.
    assert_eq!(
        fingerprint(b"key", "value").unwrap(),
        "kPv88V50o2uJ29sqch2a7P_f3dxcg-J_dZJZT3GTJIE"
    );
    assert_ne!(
        fingerprint(b"other", "value").unwrap(),
        fingerprint(b"key", "value").unwrap()
    );
    assert_eq!(
        lookup_context("p1").unwrap(),
        json!({ "protection": "p1", "use": "lookup" })
    );
    assert_eq!(
        protection_actions().unwrap()["detokenize"],
        "iam:protection:detokenize"
    );
    assert_eq!(profile_name(Some(&s("cards"))).unwrap(), "cards");
    assert_eq!(
        profile_name(Some(&s("Cards"))).unwrap_err().message,
        "Profile names are lowercase letters, digits and hyphens, starting with a letter"
    );
    assert_eq!(profile_name(None).unwrap_err().message, "Invalid profile");

    let profile: ProtectionProfile = serde_json::from_value(json!({
        "id": "p1", "tenantId": "t1", "uniqueKey": "name:cards", "name": "cards", "dataType": "card",
        "format": "random", "deterministic": false, "keyId": "k1", "mask": "last4",
        "lookupKeyWrapped": "secret", "tokens": 3, "createdAt": 1, "createdBy": "owner", "updatedAt": 2,
        "retentionDays": 30,
    }))
    .unwrap();
    let summary = serde_json::to_value(summarize_profile(&profile).unwrap()).unwrap();
    assert!(summary.get("lookupKeyWrapped").is_none());
    assert_eq!(summary["retentionDays"], json!(30.0));
    assert_eq!(summary["tokens"], json!(3.0));
    assert!(summary.get("description").is_none());
}
