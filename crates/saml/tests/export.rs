//! With `SAML_EXPORT_DIR` set, writes documents the Rust implementation signs (a signed response with a signed
//! assertion, SP metadata, a redirect login URL) for checking with the TypeScript libraries; without it, checks that
//! they verify here.

mod saml_support;

use std::sync::Arc;

use better_iam_saml::dsig::get_verified_xml;
use better_iam_saml::xml::Document;
use better_iam_saml::{SamlConfigOptions, SamlConnection, create_saml_service};
use saml_support::*;
use serde_json::json;

#[test]
fn signs_what_the_typescript_libraries_verify() {
    run(|| async {
        let idp = keys("idp");
        let sp = keys("sp");
        let assertion = format!(
            "<saml:Assertion xmlns:saml=\"{ASSERTION_NS}\" ID=\"_a1\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00.000Z\"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID>user@example.test</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"x\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">a &amp; b</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"
        );
        let response = sign(
            &format!(
                "<samlp:Response xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" ID=\"_r1\" Version=\"2.0\"><saml:Issuer>https://idp.test</saml:Issuer>{}</samlp:Response>",
                sign(&assertion, "Assertion", &idp)
            ),
            "Response",
            &idp,
        );
        let store = store_with_tenants(&["a"]).await;
        let mut config =
            SamlConfigOptions::new(store, Arc::new(|_| Box::pin(async { Ok(json!({})) })));
        config.connections = vec![SamlConnection {
            id: "enterprise".into(),
            tenant_id: "a".into(),
            entry_point: "https://idp.test/login?tenant=x&a=1".into(),
            idp_issuer: "https://idp.test".into(),
            idp_certificates: vec![idp.cert.clone()],
            entity_id: "https://iam.test/sp".into(),
            callback_url: "https://iam.test/saml/callback".into(),
            private_key: sp.private.clone(),
            public_certificate: sp.cert.clone(),
            decryption_private_key: Some(sp.private.clone()),
            decryption_certificate: Some(sp.cert.clone()),
            ..SamlConnection::default()
        }];
        let service = create_saml_service(config).unwrap();
        let metadata = service.metadata("enterprise").unwrap();
        let login = service.begin("enterprise", None, None).await.unwrap().url;
        let document = Document::parse(&response).unwrap();
        let root = document.document_element().unwrap();
        assert!(
            get_verified_xml(&response, &document, root, std::slice::from_ref(&idp.cert))
                .unwrap()
                .is_some()
        );
        let parsed = Document::parse(&metadata).unwrap();
        let entity = parsed.document_element().unwrap();
        assert!(
            get_verified_xml(&metadata, &parsed, entity, std::slice::from_ref(&sp.cert))
                .unwrap()
                .is_some()
        );
        if let Ok(directory) = std::env::var("SAML_EXPORT_DIR") {
            let directory = std::path::Path::new(&directory);
            std::fs::write(directory.join("response.xml"), &response).unwrap();
            std::fs::write(directory.join("metadata.xml"), &metadata).unwrap();
            std::fs::write(directory.join("login.txt"), &login).unwrap();
        }
    });
}
