//! Port of tests/ldap.test.ts: the LDAP primitives and the gateway over TCP, against a Better IAM instance.
//!
//! Group memberships, the service account and its grant are written to the store directly when the APIs of units
//! still being ported (`groups.addMembers`, `serviceAccounts.create`) answer NOT_IMPLEMENTED, as the server's own LDAP
//! tests do.

mod organization_fixture;

use std::sync::Arc;
use std::time::Duration;

use better_iam_auth::MfaCredential;
use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::totp;
use better_iam_core::{CredentialInput, Filter as StoreFilter};
use better_iam_ldap::{
    LdapResponse, LdapServer, LdapServerOptions, SearchOptions, SearchScope, ServerLdapIam,
    create_ldap_server, decode_response, encode_bind, encode_compare, encode_extended,
    encode_search, escape_dn_value, is_under, match_filter, normalize_dn, oid,
    paged_results_request, parse_filter, read_element, result_code,
};
use organization_fixture::{Org, assert_matches, bearer, body, ok, organization, run};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BASE: &str = "dc=acme,dc=test";
/// Final answers: bind, search done, modify, add, delete, modify DN, compare, extended.
const DONE: [u8; 8] = [0x61, 0x65, 0x67, 0x69, 0x6b, 0x6d, 0x6f, 0x78];

/// The answer to one call: the final response and the entries before it.
struct Answer {
    done: LdapResponse,
    entries: Vec<LdapResponse>,
}

/// A minimal LDAP client over TCP: one call at a time, answers collected by message ID.
struct Client {
    stream: TcpStream,
    buffer: Vec<u8>,
    received: Vec<LdapResponse>,
    next: i64,
}

impl Client {
    async fn connect(port: u16) -> Client {
        Client {
            stream: TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect"),
            buffer: Vec::new(),
            received: Vec::new(),
            next: 1,
        }
    }

    async fn call(&mut self, encode: impl FnOnce(i64) -> Vec<u8>) -> Answer {
        let id = self.next;
        self.next += 1;
        self.stream.write_all(&encode(id)).await.expect("write");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(done) = self
                .received
                .iter()
                .find(|response| response.id == id && DONE.contains(&response.tag))
                .cloned()
            {
                let entries = self
                    .received
                    .iter()
                    .filter(|response| response.id == id && response.tag == 0x64)
                    .cloned()
                    .collect();
                return Answer { done, entries };
            }
            let mut chunk = vec![0u8; 65536];
            let read = tokio::time::timeout_at(deadline, self.stream.read(&mut chunk))
                .await
                .unwrap_or_else(|_| panic!("No answer to request {id}"))
                .expect("read");
            if read == 0 {
                let notice = self
                    .received
                    .iter()
                    .find(|response| response.id == 0)
                    .and_then(|r| r.message.clone());
                panic!("Connection closed: {notice:?}");
            }
            self.buffer.extend_from_slice(&chunk[..read]);
            while let Some(item) = read_element(&self.buffer, 0, 1 << 24).expect("BER") {
                let size = item.size;
                let response = decode_response(&item).expect("response");
                self.received.push(response);
                self.buffer.drain(..size);
            }
        }
    }

    async fn bind(&mut self, name: &str, password: &str) -> Answer {
        self.call(|id| encode_bind(id, name, password)).await
    }

    async fn search(
        &mut self,
        base: &str,
        filter: &str,
        scope: Option<SearchScope>,
        attributes: &[&str],
        controls: Option<Vec<u8>>,
    ) -> Answer {
        let search = SearchOptions {
            base: base.to_owned(),
            scope,
            filter: parse_filter(filter).unwrap(),
            attributes: attributes.iter().map(|name| (*name).to_owned()).collect(),
            size_limit: None,
            types_only: false,
        };
        self.call(|id| encode_search(id, &search, controls)).await
    }

    async fn compare(&mut self, entry: &str, attribute: &str, value: &str) -> Answer {
        self.call(|id| encode_compare(id, entry, attribute, value))
            .await
    }

    async fn who_am_i(&mut self) -> Answer {
        self.call(|id| encode_extended(id, oid::WHO_AM_I, None))
            .await
    }

    /// A delete request (`[APPLICATION 10]`), which a read-only directory refuses.
    async fn remove(&mut self, dn: &str) -> Answer {
        self.call(|id| {
            let name = dn.as_bytes();
            let mut body = vec![0x02, 0x01, id as u8, 0x4a, name.len() as u8];
            body.extend_from_slice(name);
            let mut out = vec![0x30, body.len() as u8];
            out.extend(body);
            out
        })
        .await
    }
}

fn code(answer: &Answer) -> i64 {
    answer.done.code.expect("result code")
}

fn attribute<'a>(response: &'a LdapResponse, name: &str) -> &'a [String] {
    response
        .attributes
        .as_ref()
        .and_then(|attributes| attributes.get(name))
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

struct Setup {
    f: Org,
    key: CredentialInput,
    settings: Value,
    port: u16,
    #[allow(dead_code)]
    gateway: LdapServer,
}

async fn add_member(f: &Org, group: &str, identity: &str) {
    let added = f
        .iam
        .api
        .groups
        .add_members(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "groupId": group, "identityIds": [identity] })),
        )
        .await;
    match added {
        Ok(_) => {}
        Err(error)
            if error.code == "NOT_IMPLEMENTED"
                && f.find(
                    "groupMembers",
                    StoreFilter::new().eq("groupId", group.to_owned()),
                )
                .await
                .is_empty() =>
        {
            f.insert(
                "groupMembers",
                json!({
                    "id": better_iam_server::utils::id(),
                    "tenantId": f.tenant_id,
                    "uniqueKey": format!("{group}:{identity}"),
                    "groupId": group,
                    "identityId": identity,
                }),
            )
            .await;
        }
        Err(error) if error.code == "NOT_IMPLEMENTED" => {}
        Err(error) => panic!("addMembers: {error:?}"),
    }
}

async fn service_account(f: &Org) -> String {
    match f
        .iam
        .api
        .service_accounts
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "name": "vpn" })),
        )
        .await
    {
        Ok(reply) => reply.into_value().unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        // The account commits before package automation (still a skeleton) runs.
        Err(error) if error.code == "NOT_IMPLEMENTED" => {
            let committed = f
                .find(
                    "identities",
                    StoreFilter::new()
                        .eq("tenantId", f.tenant_id.clone())
                        .eq("name", "vpn"),
                )
                .await;
            if let Some(account) = committed.first() {
                return account["id"].as_str().unwrap().to_owned();
            }
            let id = better_iam_server::utils::id();
            f.insert(
                "identities",
                json!({
                    "id": id,
                    "tenantId": f.tenant_id,
                    "kind": "service",
                    "name": "vpn",
                    "status": "active",
                    "emailVerified": false,
                    "rootAdmin": false,
                    "owner": false,
                    "createdAt": f.now(),
                }),
            )
            .await;
            id
        }
        Err(error) => panic!("serviceAccounts.create: {error:?}"),
    }
}

/// Acme publishing its directory under dc=acme,dc=test, with a directory reader service account and a gateway.
async fn setup() -> Setup {
    let f = organization(|_| {}).await;
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    f.member("bob").await;
    let engineering = ok(f
        .iam
        .api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "name": "Engineering" })),
        )
        .await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    add_member(&f, &engineering, &alice).await;
    let reader = service_account(&f).await;
    f.grant(
        &reader,
        json!([{ "effect": "allow", "actions": ["iam:ldap:read"], "resources": ["*"] }]),
    )
    .await;
    let key = bearer(
        ok(f.iam
            .api
            .credentials
            .create(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": reader })),
            )
            .await)["token"]
            .as_str()
            .unwrap(),
    );
    let settings = ok(f
        .iam
        .api
        .ldap
        .update_settings(
            &owner,
            body(json!({
                "tenantId": f.tenant_id,
                "enabled": true,
                "baseDn": "dc=acme, dc=test",
                "includeServiceAccounts": true,
            })),
        )
        .await);
    let mut options = LdapServerOptions::new(Arc::new(ServerLdapIam::new(&f.iam).unwrap()));
    options.cache_ms = Some(0.0);
    let gateway = create_ldap_server(options);
    let port = gateway.listen(Some(0), None).await.unwrap().port();
    Setup {
        f,
        key,
        settings,
        port,
        gateway,
    }
}

#[test]
fn normalizes_and_escapes_dns_and_matches_filters() {
    assert_eq!(
        normalize_dn("UID=Alice,  OU=People , DC=Acme,DC=Test").unwrap(),
        "uid=alice,ou=people,dc=acme,dc=test"
    );
    assert_eq!(escape_dn_value("Smith, John+1"), "Smith\\, John\\+1");
    assert!(is_under("uid=a,ou=people,dc=acme,dc=test", "dc=acme,dc=test").unwrap());
    assert!(!is_under("dc=acme,dc=test", "ou=people,dc=acme,dc=test").unwrap());
    let mut entry = better_iam_ldap::EntryAttributes::new();
    entry.insert(
        "objectclass".into(),
        vec!["top".into(), "inetOrgPerson".into()],
    );
    entry.insert("mail".into(), vec!["alice@acme.test".into()]);
    entry.insert("cn".into(), vec!["Alice Liddell".into()]);
    assert!(match_filter(
        &parse_filter("(&(objectClass=inetOrgPerson)(mail=ALICE@acme.test))").unwrap(),
        &entry
    ));
    assert!(!match_filter(
        &parse_filter("(|(cn=Bob*)(!(mail=*)))").unwrap(),
        &entry
    ));
    assert!(match_filter(&parse_filter("(cn=*Lid*)").unwrap(), &entry));
    assert!(!match_filter(&parse_filter("(title=*)").unwrap(), &entry));
    assert!(parse_filter("(cn=unbalanced").is_err());
}

/// The size and cookie of a paged results response control value.
fn read_paged(value: &[u8]) -> (u64, Vec<u8>) {
    let outer = read_element(value, 0, value.len()).unwrap().unwrap();
    let size = read_element(outer.value, 0, outer.value.len())
        .unwrap()
        .unwrap();
    let cookie = read_element(outer.value, size.size, outer.value.len())
        .unwrap()
        .unwrap();
    (
        size.value
            .iter()
            .fold(0u64, |acc, byte| acc * 256 + *byte as u64),
        cookie.value.to_vec(),
    )
}

#[test]
fn lets_people_and_service_accounts_bind_and_serves_the_directory_each_may_read() {
    run(|| async {
        let Setup {
            f,
            settings,
            port,
            key,
            gateway,
        } = setup().await;
        assert_matches(
            &settings,
            json!({ "enabled": true, "baseDn": BASE, "uid": "email", "attributes": [] }),
        );
        let mut client = Client::connect(port).await;

        // Before a bind: the root DSE only.
        let dse = client
            .search("", "(objectClass=*)", Some(SearchScope::Base), &[], None)
            .await;
        assert_eq!(attribute(&dse.entries[0], "supportedLDAPVersion"), ["3"]);
        assert_eq!(
            code(
                &client
                    .search(BASE, "(objectClass=*)", None, &[], None)
                    .await
            ),
            result_code::INSUFFICIENT_ACCESS_RIGHTS
        );

        // People bind with their password, under the uid the organization chose.
        let alice = format!("uid=alice@acme.test,ou=people,{BASE}");
        assert_eq!(
            code(&client.bind(&alice, "wrong password").await),
            result_code::INVALID_CREDENTIALS
        );
        assert_eq!(
            code(&client.bind(&alice, "").await),
            result_code::UNWILLING_TO_PERFORM
        );
        assert_eq!(
            code(
                &client
                    .bind(&format!("uid=nobody@acme.test,ou=people,{BASE}"), "x")
                    .await
            ),
            result_code::INVALID_CREDENTIALS
        );
        // DNs compare without regard to case.
        assert_eq!(
            code(
                &client
                    .bind(&alice.to_uppercase(), "a strong alice password")
                    .await
            ),
            result_code::SUCCESS
        );
        assert_eq!(
            client
                .who_am_i()
                .await
                .done
                .response_value
                .map(|value| String::from_utf8(value).unwrap()),
            Some(format!("dn:{}", alice.to_uppercase()))
        );

        // Without iam:ldap:read a person sees only their own entry, and their groups with only them in it.
        let own = client
            .search(
                BASE,
                "(|(objectClass=inetOrgPerson)(objectClass=groupOfNames))",
                None,
                &[],
                None,
            )
            .await;
        assert_eq!(code(&own), result_code::SUCCESS);
        let mut dns: Vec<String> = own
            .entries
            .iter()
            .map(|entry| entry.dn.clone().unwrap())
            .collect();
        dns.sort();
        let mut expected = vec![format!("cn=Engineering,ou=groups,{BASE}"), alice.clone()];
        expected.sort();
        assert_eq!(dns, expected);
        let own_entry = own
            .entries
            .iter()
            .find(|entry| entry.dn.as_deref() == Some(alice.as_str()))
            .unwrap();
        assert_eq!(attribute(own_entry, "mail"), ["alice@acme.test"]);
        assert_eq!(
            attribute(own_entry, "memberOf"),
            [format!("cn=Engineering,ou=groups,{BASE}")]
        );
        assert_eq!(
            code(&client.compare(&alice, "mail", "alice@acme.test").await),
            result_code::COMPARE_TRUE
        );
        assert_eq!(
            code(&client.compare(&alice, "mail", "bob@acme.test").await),
            result_code::COMPARE_FALSE
        );
        // The directory is read-only, and other trees do not exist for this binding.
        assert_eq!(
            code(&client.remove(&alice).await),
            result_code::UNWILLING_TO_PERFORM
        );
        assert_eq!(
            code(
                &client
                    .search("dc=other,dc=test", "(objectClass=*)", None, &[], None)
                    .await
            ),
            result_code::NO_SUCH_OBJECT
        );

        // A service account binds with an API key; with iam:ldap:read it reads the whole published directory.
        assert_eq!(
            code(
                &client
                    .bind(
                        &format!("cn=vpn,ou=services,{BASE}"),
                        key.token.as_deref().unwrap()
                    )
                    .await
            ),
            result_code::SUCCESS
        );
        let people = client
            .search(
                &format!("ou=people,{BASE}"),
                "(objectClass=inetOrgPerson)",
                Some(SearchScope::One),
                &["mail", "memberOf"],
                None,
            )
            .await;
        let mut mails: Vec<String> = people
            .entries
            .iter()
            .map(|entry| attribute(entry, "mail")[0].clone())
            .collect();
        mails.sort();
        assert_eq!(
            mails,
            ["alice@acme.test", "bob@acme.test", "owner@acme.test"]
        );
        let group = client
            .search(
                &format!("cn=Engineering,ou=groups,{BASE}"),
                "(objectClass=*)",
                Some(SearchScope::Base),
                &[],
                None,
            )
            .await;
        assert_eq!(
            attribute(&group.entries[0], "member"),
            std::slice::from_ref(&alice)
        );
        let services = client
            .search(
                &format!("ou=services,{BASE}"),
                "(cn=vpn)",
                Some(SearchScope::One),
                &[],
                None,
            )
            .await;
        assert_eq!(services.entries.len(), 1);

        // Paged results (RFC 2696) walk the people one page at a time.
        let mut seen: Vec<String> = Vec::new();
        let mut cookie: Vec<u8> = Vec::new();
        loop {
            let page = client
                .search(
                    &format!("ou=people,{BASE}"),
                    "(objectClass=inetOrgPerson)",
                    Some(SearchScope::One),
                    &[],
                    Some(paged_results_request(2, &cookie)),
                )
                .await;
            seen.extend(page.entries.iter().map(|entry| entry.dn.clone().unwrap()));
            let control = page
                .done
                .controls
                .as_ref()
                .and_then(|controls| controls.iter().find(|item| item.kind == oid::PAGED_RESULTS))
                .unwrap();
            let (_, next) = read_paged(control.value.as_deref().unwrap());
            cookie = next;
            if cookie.is_empty() {
                break;
            }
        }
        assert_eq!(seen.len(), 3);

        let reads = ok(f
            .iam
            .api
            .audit
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "action": "ldap:directory:read" })),
            )
            .await);
        let events = match &reads {
            Value::Array(items) => items.clone(),
            other => other["events"].as_array().cloned().unwrap_or_default(),
        };
        assert!(!events.is_empty());
        drop(client);
        gateway.close().await;
    });
}

#[test]
fn takes_the_one_time_code_after_the_password_from_people_who_use_mfa_and_stops_when_turned_off() {
    run(|| async {
        let Setup {
            f, port, gateway, ..
        } = setup().await;
        let bob_id = f
            .find(
                "identities",
                StoreFilter::new().eq("email", "bob@acme.test"),
            )
            .await
            .first()
            .map(|record| record["id"].as_str().unwrap().to_owned())
            .unwrap();
        let first = f.sign_in(&bob_id).await;
        let credential = MfaCredential::Credential(first.clone());
        let enrollment = f.iam.auth.begin_mfa(&credential).await.unwrap();
        f.iam
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: totp::generate(&enrollment.secret, f.now()).unwrap(),
                remember_device: false,
            })
            .await
            .unwrap();
        f.advance(30_000.0);
        let mut client = Client::connect(port).await;
        let bob = format!("uid=bob@acme.test,ou=people,{BASE}");
        assert_eq!(
            code(&client.bind(&bob, "a strong bob password").await),
            result_code::INVALID_CREDENTIALS
        );
        let with_code = format!(
            "a strong bob password{}",
            totp::generate(&enrollment.secret, f.now()).unwrap()
        );
        assert_eq!(
            code(&client.bind(&bob, &with_code).await),
            result_code::SUCCESS
        );

        // Only declared identity attributes can be published.
        let refused = f
            .iam
            .api
            .ldap
            .update_settings(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "attributes": ["salary"] })),
            )
            .await;
        assert_eq!(
            refused.err().map(|error| error.code),
            Some("INVALID_INPUT".to_owned())
        );

        ok(f.iam
            .api
            .ldap
            .update_settings(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "enabled": false })),
            )
            .await);
        assert_eq!(
            code(
                &client
                    .bind(
                        &format!("uid=alice@acme.test,ou=people,{BASE}"),
                        "a strong alice password"
                    )
                    .await
            ),
            result_code::INVALID_CREDENTIALS
        );
        drop(client);
        gateway.close().await;
    });
}
