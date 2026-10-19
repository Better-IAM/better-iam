//! Shared fixtures for the ported authentication tests: an in-memory SQLite store, a controllable clock, captured
//! deliveries, a tenant tree, and a virtual WebAuthn authenticator producing real P-256 responses
//! (`tests/support/webauthn.ts`).
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::crypto::random_bytes;
use better_iam_auth::service::CreateIdentityInput;
use better_iam_auth::types::{
    AuthOptions, DeliveryMessage, PasskeyOptions, SessionResult, SignInResult,
};
use better_iam_auth::util::base64url;
use better_iam_auth::webauthn::cbor::{Cbor, encode};
use better_iam_auth::{AuthService, create_auth, delivery_fn};
use better_iam_core::{CredentialInput, IamError, IamStore, IamStoreExt, Identity, record};
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SECRET: &str = "test-secret-32-characters-minimum-better-iam";
pub const PASSWORD: &str = "test-password-long-enough";

/// A clock tests move by hand.
#[derive(Clone)]
pub struct Clock(Arc<Mutex<f64>>);

impl Clock {
    pub fn new(at: f64) -> Self {
        Self(Arc::new(Mutex::new(at)))
    }

    pub fn now(&self) -> f64 {
        *self.0.lock().unwrap()
    }

    pub fn advance(&self, ms: f64) {
        *self.0.lock().unwrap() += ms;
    }
}

/// The deliveries the service handed to its callbacks.
#[derive(Clone, Default)]
pub struct Inbox(Arc<Mutex<Vec<DeliveryMessage>>>);

impl Inbox {
    pub fn all(&self) -> Vec<DeliveryMessage> {
        self.0.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn last(&self, template: &str) -> DeliveryMessage {
        self.all()
            .into_iter()
            .rev()
            .find(|message| message.template == template)
            .unwrap_or_else(|| panic!("no {template} message"))
    }

    pub fn token(&self, index: usize) -> String {
        self.all()[index].payload["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

pub struct Fixture {
    pub store: Arc<dyn IamStore>,
    pub auth: AuthService,
    pub clock: Clock,
    pub inbox: Inbox,
}

pub fn now_ms() -> f64 {
    better_iam_core::js::now_ms()
}

/// `auth.test.ts`'s service: sign-up, email and SMS delivery, passwordless email and SMS, passkeys for
/// `iam.example.com`.
pub async fn fixture() -> Fixture {
    fixture_with(|_| {}).await
}

pub async fn fixture_with(configure: impl FnOnce(&mut AuthOptions)) -> Fixture {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("store");
    store.migrate().await.expect("migrate");
    let clock = Clock::new(now_ms());
    let inbox = Inbox::default();
    let mut options = AuthOptions::new(store.clone(), SECRET, "https://iam.example.com");
    options.sign_up_enabled = Some(true);
    let email_inbox = inbox.clone();
    options.send_email = Some(delivery_fn(move |message| {
        let inbox = email_inbox.clone();
        async move {
            inbox.0.lock().unwrap().push(message);
            Ok(())
        }
    }));
    let sms_inbox = inbox.clone();
    options.send_sms = Some(delivery_fn(move |message| {
        let inbox = sms_inbox.clone();
        async move {
            inbox.0.lock().unwrap().push(message);
            Ok(())
        }
    }));
    options.passwordless_email = Some(true);
    options.passwordless_sms = Some(true);
    options.passkeys = Some(PasskeyOptions {
        rp_id: "iam.example.com".to_owned(),
        rp_name: None,
    });
    let time = clock.clone();
    options.now = Some(Arc::new(move || time.now()));
    configure(&mut options);
    let auth = create_auth(options).expect("auth service");
    let at = clock.now();
    store
        .transaction(|tx| async move {
            for (id, parent, kind) in [
                ("root", None, "root"),
                ("org", Some("root"), "organization"),
                ("sibling", Some("root"), "organization"),
                ("project", Some("org"), "project"),
            ] {
                tx.insert(
                    "tenants",
                    &record(json!({
                        "id": id,
                        "tenantId": id,
                        "name": id,
                        "parentId": parent,
                        "type": kind,
                        "status": "active",
                        "createdAt": at,
                    })),
                )
                .await?;
            }
            Ok(())
        })
        .await
        .expect("tenants");
    Fixture {
        store,
        auth,
        clock,
        inbox,
    }
}

impl Fixture {
    /// `identity(tenantId, { rootAdmin, email })`: a verified person with [`PASSWORD`].
    pub async fn identity(
        &self,
        tenant_id: &str,
        root_admin: bool,
        email: Option<&str>,
    ) -> Identity {
        let input = CreateIdentityInput {
            tenant_id: tenant_id.to_owned(),
            email: email.unwrap_or("same@example.com").to_owned(),
            name: "Test User".to_owned(),
            password: Some(PASSWORD.to_owned()),
            owner: None,
            root_admin: Some(root_admin),
            email_verified: Some(true),
        };
        let auth = self.auth.clone();
        self.store
            .transaction(|tx| async move { auth.create_identity(&tx, input).await })
            .await
            .expect("identity")
    }

    pub async fn sign_in(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
    ) -> Result<SignInResult, IamError> {
        self.auth
            .sign_in(&json!({ "tenantId": tenant_id, "email": email, "password": password }))
            .await
    }

    pub async fn session(&self, tenant_id: &str) -> SessionResult {
        session(
            self.sign_in(tenant_id, "same@example.com", PASSWORD)
                .await
                .expect("sign in"),
        )
    }

    /// The current code of an authenticator secret.
    pub fn totp(&self, secret: &str) -> String {
        better_iam_auth::totp::generate(secret, self.clock.now()).unwrap()
    }

    pub async fn get(&self, collection: &str, id: &str) -> Option<better_iam_core::Record> {
        self.store.get(collection, id).await.unwrap()
    }

    pub async fn all(&self, collection: &str) -> Vec<better_iam_core::Record> {
        self.store
            .find(collection, &Default::default(), &Default::default())
            .await
            .unwrap()
    }
}

pub fn session(result: SignInResult) -> SessionResult {
    match result {
        SignInResult::Session(session) => session,
        SignInResult::MfaRequired(_) => panic!("Unexpected MFA challenge"),
    }
}

pub fn token(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub fn headers(pairs: &[(&str, &str)]) -> CredentialInput {
    CredentialInput {
        headers: Some(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        ),
        token: None,
    }
}

/// Asserts the error code of a refused call.
#[track_caller]
pub fn code<T: std::fmt::Debug>(result: Result<T, IamError>) -> String {
    match result {
        Ok(value) => panic!("expected an error, got {value:?}"),
        Err(error) => error.code,
    }
}

/// A virtual platform authenticator for one relying party: real P-256 registration and assertion responses
/// (user-verified, resident), so the verifier runs unmocked.
pub struct VirtualAuthenticator {
    pub credential_id: Vec<u8>,
    key: p256::ecdsa::SigningKey,
    rp_hash: Vec<u8>,
    counter: u32,
    pub origin: String,
}

impl VirtualAuthenticator {
    pub fn new(rp_id: &str, origin: &str) -> Self {
        Self {
            credential_id: random_bytes(32),
            key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            rp_hash: Sha256::digest(rp_id.as_bytes()).to_vec(),
            counter: 0,
            origin: origin.to_owned(),
        }
    }

    pub fn id(&self) -> String {
        base64url(&self.credential_id)
    }

    fn cose(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_encoded_point(false);
        encode(&Cbor::Map(vec![
            (Cbor::Number(1.0), Cbor::Number(2.0)),
            (Cbor::Number(3.0), Cbor::Number(-7.0)),
            (Cbor::Number(-1.0), Cbor::Number(1.0)),
            (Cbor::Number(-2.0), Cbor::Bytes(point.x().unwrap().to_vec())),
            (Cbor::Number(-3.0), Cbor::Bytes(point.y().unwrap().to_vec())),
        ]))
    }

    /// A `none` attestation for `challenge`, flags UP|UV|AT.
    pub fn register(&self, challenge: &str) -> Value {
        self.register_with(
            challenge,
            "none",
            Cbor::Map(Vec::new()),
            0x45,
            json!(["internal"]),
        )
    }

    pub fn register_with(
        &self,
        challenge: &str,
        fmt: &str,
        att_stmt: Cbor,
        flags: u8,
        transports: Value,
    ) -> Value {
        let mut auth_data = self.rp_hash.clone();
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&[0, self.credential_id.len() as u8]);
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend(self.cose());
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": self.origin,
        }))
        .unwrap();
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": base64url(&client_data),
                "attestationObject": base64url(encode(&Cbor::Map(vec![
                    (Cbor::Text("fmt".to_owned()), Cbor::Text(fmt.to_owned())),
                    (Cbor::Text("attStmt".to_owned()), att_stmt),
                    (Cbor::Text("authData".to_owned()), Cbor::Bytes(auth_data)),
                ]))),
                "transports": transports,
            },
        })
    }

    /// Signs `data` with the credential key (DER signature).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: p256::ecdsa::Signature = self.key.sign(data);
        signature.to_der().as_bytes().to_vec()
    }

    /// An assertion for `challenge` with a fresh counter.
    pub fn assert(&mut self, challenge: &str, user_id: &str, origin: Option<&str>) -> Value {
        self.counter += 1;
        self.assert_with(challenge, user_id, origin, self.counter, 0x05)
    }

    pub fn assert_with(
        &self,
        challenge: &str,
        user_id: &str,
        origin: Option<&str>,
        counter: u32,
        flags: u8,
    ) -> Value {
        let mut auth_data = self.rp_hash.clone();
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin.unwrap_or(&self.origin),
        }))
        .unwrap();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": base64url(&client_data),
                "authenticatorData": base64url(&auth_data),
                "signature": base64url(self.sign(&signed)),
                "userHandle": base64url(user_id.as_bytes()),
            },
        })
    }
}

/// Records `client` on everything the future does (`auth.withClient(client, fn)`).
pub fn client(
    ip: Option<&str>,
    user_agent: Option<&str>,
    label: Option<&str>,
) -> better_iam_core::SessionClientInfo {
    better_iam_core::SessionClientInfo {
        ip: ip.map(str::to_owned),
        user_agent: user_agent.map(str::to_owned),
        label: label.map(str::to_owned),
        extra: Default::default(),
    }
}

pub const ROOT_PASSWORD: &str = "a strong root test password";

/// A deployment shaped like the server tests' `betterIam(...)` + `bootstrap(...)`: base URL
/// `http://localhost:3000`, email delivery captured, the clock injected, a root tenant `root` with the root
/// administrator `root@example.test`, and an organization `org` under it.
pub async fn server(configure: impl FnOnce(&mut AuthOptions)) -> Fixture {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("store");
    store.migrate().await.expect("migrate");
    let clock = Clock::new(now_ms());
    let inbox = Inbox::default();
    let mut options = AuthOptions::new(
        store.clone(),
        "server-shaped-test-secret-with-at-least-32-chars",
        "http://localhost:3000",
    );
    let email_inbox = inbox.clone();
    options.send_email = Some(delivery_fn(move |message| {
        let inbox = email_inbox.clone();
        async move {
            inbox.0.lock().unwrap().push(message);
            Ok(())
        }
    }));
    let time = clock.clone();
    options.now = Some(Arc::new(move || time.now()));
    configure(&mut options);
    let store = options.store.clone();
    store.migrate().await.expect("migrate");
    let auth = create_auth(options).expect("auth service");
    let at = clock.now();
    store
        .transaction(|tx| async move {
            for (id, parent, kind) in [
                ("root", None, "root"),
                ("org", Some("root"), "organization"),
            ] {
                tx.insert(
                    "tenants",
                    &record(json!({
                        "id": id, "tenantId": id, "name": id, "parentId": parent, "type": kind,
                        "status": "active", "createdAt": at,
                    })),
                )
                .await?;
            }
            Ok(())
        })
        .await
        .expect("tenants");
    let f = Fixture {
        store,
        auth,
        clock,
        inbox,
    };
    f.person(
        "root",
        "root@example.test",
        "Root",
        ROOT_PASSWORD,
        true,
        true,
    )
    .await;
    f
}

impl Fixture {
    /// Creates a person in a tenant.
    pub async fn person(
        &self,
        tenant_id: &str,
        email: &str,
        name: &str,
        password: &str,
        verified: bool,
        root_admin: bool,
    ) -> Identity {
        let input = CreateIdentityInput {
            tenant_id: tenant_id.to_owned(),
            email: email.to_owned(),
            name: name.to_owned(),
            password: Some(password.to_owned()),
            owner: None,
            root_admin: Some(root_admin),
            email_verified: Some(verified),
        };
        let auth = self.auth.clone();
        self.store
            .transaction(|tx| async move { auth.create_identity(&tx, input).await })
            .await
            .expect("person")
    }

    /// Replaces (or with None removes) a tenant's `authPolicy`.
    pub async fn set_policy(&self, tenant_id: &str, policy: Option<Value>) {
        let id = tenant_id.to_owned();
        self.store
            .transaction(|tx| async move {
                let mut tenant = tx.get("tenants", &id).await?.unwrap();
                match policy {
                    Some(policy) => {
                        tenant.insert("authPolicy".to_owned(), policy);
                    }
                    None => {
                        tenant.remove("authPolicy");
                    }
                }
                tx.put("tenants", &tenant).await?;
                Ok(())
            })
            .await
            .unwrap();
    }

    /// Sets members of a stored record.
    pub async fn patch(&self, collection: &str, id: &str, changes: Value) {
        let (collection, id) = (collection.to_owned(), id.to_owned());
        self.store
            .transaction(|tx| async move {
                let mut stored = tx.get(&collection, &id).await?.unwrap();
                for (key, value) in changes.as_object().unwrap() {
                    if value.is_null() {
                        stored.remove(key);
                    } else {
                        stored.insert(key.clone(), value.clone());
                    }
                }
                tx.put(&collection, &stored).await?;
                Ok(())
            })
            .await
            .unwrap();
    }

    pub async fn find(&self, collection: &str, filter: Value) -> Vec<better_iam_core::Record> {
        self.store
            .find(
                collection,
                &better_iam_core::Filter::from(record(filter)),
                &Default::default(),
            )
            .await
            .unwrap()
    }

    /// Signs in with a password, optionally from a client.
    pub async fn sign_in_from(
        &self,
        client: Option<better_iam_core::SessionClientInfo>,
        tenant_id: &str,
        email: &str,
        password: &str,
    ) -> Result<SignInResult, IamError> {
        let input = json!({ "tenantId": tenant_id, "email": email, "password": password });
        self.auth
            .with_client(client, self.auth.sign_in(&input))
            .await
    }

    /// The `auth:signin:fail` events of an identity, in chain order.
    pub async fn failures(
        &self,
        tenant_id: &str,
        identity_id: &str,
    ) -> Vec<better_iam_core::Record> {
        let mut events: Vec<_> = self
            .find(
                "audit",
                json!({ "tenantId": tenant_id, "actorId": identity_id }),
            )
            .await
            .into_iter()
            .filter(|event| event["action"] == "auth:signin:fail")
            .collect();
        events.sort_by(|a, b| {
            a["sequence"]
                .as_f64()
                .partial_cmp(&b["sequence"].as_f64())
                .unwrap()
        });
        events
    }

    pub fn messages(&self, template: &str) -> Vec<DeliveryMessage> {
        self.inbox
            .all()
            .into_iter()
            .filter(|message| message.template == template)
            .collect()
    }
}

/// Enrolls an authenticator from a session; returns the secret and the confirmation.
pub async fn enroll(
    f: &Fixture,
    session_token: &str,
) -> (String, better_iam_auth::service::mfa::ConfirmedMfa) {
    let credential = better_iam_auth::types::MfaCredential::Credential(token(session_token));
    let enrollment = f.auth.begin_mfa(&credential).await.expect("begin MFA");
    let confirmed = f
        .auth
        .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
            credential,
            code: f.totp(&enrollment.secret),
            remember_device: false,
        })
        .await
        .expect("confirm MFA");
    (enrollment.secret, confirmed)
}

/// JSON equality with JavaScript number semantics (`2.0` equals `2`), order-insensitive for object members.
#[track_caller]
pub fn assert_json(left: &Value, right: &Value) {
    assert!(
        better_iam_core::js::deep_equal(left, right),
        "JSON differs:\n  left: {left}\n right: {right}"
    );
}

impl VirtualAuthenticator {
    /// The private key as JWK members `d`, `x`, `y` (base64url).
    pub fn export(&self) -> (String, String, String) {
        let point = self.key.verifying_key().to_encoded_point(false);
        (
            base64url(self.key.to_bytes()),
            base64url(point.x().unwrap()),
            base64url(point.y().unwrap()),
        )
    }
}
