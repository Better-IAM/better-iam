//! Ports of `tests/safe-fetch.test.ts` and `tests/safe-fetch-cancel.test.ts`, against a small HTTP/1.1 server on
//! the loopback interface.

use std::time::{Duration, Instant};

use better_iam_auth::safe_fetch::{FetchBody, FetchRequest, RedirectMode};
use better_iam_auth::{
    GuardedFetchOptions, SafeFetchAddressOptions, SafeFetchError, SafeFetchFailureReason,
    SafeFetchOptions, check_fetch_url, create_guarded_fetch, fetch_json_safely, is_public_address,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const STRICT: SafeFetchOptions = SafeFetchOptions {
    timeout_ms: 1000,
    max_bytes: 1024,
    allow_private_networks: false,
    allow_insecure_localhost: false,
};
const LOCAL: SafeFetchOptions = SafeFetchOptions {
    timeout_ms: 1000,
    max_bytes: 1024,
    allow_private_networks: false,
    allow_insecure_localhost: true,
};

fn strict_address() -> SafeFetchAddressOptions {
    SafeFetchAddressOptions::from(&STRICT)
}

fn local_address() -> SafeFetchAddressOptions {
    SafeFetchAddressOptions::from(&LOCAL)
}

#[test]
fn treats_public_addresses_as_public() {
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "100.63.255.255",
        "100.128.0.1",
        "172.32.0.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001:830::200e",
        "::ffff:8.8.8.8",
    ] {
        assert!(is_public_address(address), "{address}");
    }
}

#[test]
fn refuses_private_and_reserved_addresses() {
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "127.255.0.9",
        "169.254.169.254",
        "172.16.5.4",
        "172.31.255.255",
        "192.0.0.8",
        "192.0.2.10",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:a9fe:a9fe",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
        "::127.0.0.1",
        "::a00:1",
        "::a9fe:a9fe",
        "100::1",
        "2001::1",
        "2001:10::1",
        "2001:db8::1",
        "2002:0a00::",
        "2002:808:808::1",
        "fd00::1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ] {
        assert!(!is_public_address(address), "{address}");
    }
}

#[test]
fn refuses_malformed_values() {
    for address in [
        "",
        "example.com",
        "1.2.3",
        "01.2.3.4",
        "256.1.1.1",
        "fe80::1%eth0",
        "[::1]",
        "1.2.3.4/32",
    ] {
        assert!(!is_public_address(address), "{address:?}");
    }
}

fn reason(result: Result<impl std::fmt::Debug, SafeFetchError>) -> SafeFetchFailureReason {
    match result {
        Ok(value) => panic!("expected a SafeFetchError, got {value:?}"),
        Err(error) => error.reason,
    }
}

#[test]
fn accepts_https_on_the_default_port() {
    assert_eq!(
        check_fetch_url(
            "https://idp.example.com/.well-known/jwks.json",
            &strict_address()
        )
        .unwrap()
        .as_str(),
        "https://idp.example.com/.well-known/jwks.json"
    );
    assert_eq!(
        check_fetch_url("https://idp.example.com:443/keys?x=1", &strict_address())
            .unwrap()
            .port(),
        None
    );
    assert_eq!(
        check_fetch_url("https://8.8.8.8/keys", &strict_address())
            .unwrap()
            .host_str(),
        Some("8.8.8.8")
    );
}

#[test]
fn refuses_urls_against_the_rules() {
    use SafeFetchFailureReason::{Address, Url};
    for (url, expected) in [
        ("http://idp.example.com/jwks", Url),
        ("https://idp.example.com:8443/jwks", Url),
        ("https://user:secret@idp.example.com/jwks", Url),
        ("https://idp.example.com/jwks#keys", Url),
        ("https://idp.example.com/jwks#", Url),
        ("/jwks", Url),
        ("file:///etc/passwd", Url),
        ("http://localhost:8080/jwks", Url),
        ("https://10.0.0.1/jwks", Address),
        ("https://169.254.169.254/latest/meta-data", Address),
        ("https://[::1]/jwks", Address),
        ("https://[::ffff:10.0.0.1]/jwks", Address),
        ("https://[fd00::1]/jwks", Address),
    ] {
        assert_eq!(
            reason(check_fetch_url(url, &strict_address())),
            expected,
            "{url}"
        );
    }
}

#[test]
fn lets_private_literals_through_only_with_allow_private_networks() {
    let mut options = strict_address();
    options.allow_private_networks = true;
    assert_eq!(
        check_fetch_url("https://10.0.0.1/jwks", &options)
            .unwrap()
            .host_str(),
        Some("10.0.0.1")
    );
    assert_eq!(
        reason(check_fetch_url("http://10.0.0.1/jwks", &options)),
        SafeFetchFailureReason::Url
    );
}

#[test]
fn allows_http_and_any_port_on_loopback_hosts_with_allow_insecure_localhost() {
    for url in [
        "http://127.0.0.1:9000/jwks",
        "http://localhost:9000/jwks",
        "http://[::1]:9000/",
    ] {
        assert_eq!(
            check_fetch_url(url, &local_address()).unwrap().scheme(),
            "http",
            "{url}"
        );
    }
    assert_eq!(
        reason(check_fetch_url("http://10.0.0.1:9000/", &local_address())),
        SafeFetchFailureReason::Url
    );
    assert_eq!(
        reason(check_fetch_url("ftp://127.0.0.1/", &local_address())),
        SafeFetchFailureReason::Url
    );
}

/// A tiny HTTP/1.1 server with the routes of the TypeScript test.
async fn server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handle(stream));
        }
    });
    base
}

async fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
}

async fn handle(mut stream: TcpStream) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    }
    let request = String::from_utf8_lossy(&buffer).into_owned();
    let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let json = ("content-type", "application/json");
    match path.as_str() {
        "/ok" => {
            respond(
                &mut stream,
                "200 OK",
                &[("content-type", "application/json; charset=utf-8")],
                br#"{"keys":[{"kid":"a"}]}"#,
            )
            .await
        }
        "/jwk-set" => {
            respond(
                &mut stream,
                "200 OK",
                &[("content-type", "application/jwk-set+json")],
                br#"{"keys":[]}"#,
            )
            .await
        }
        "/redirect" => {
            respond(
                &mut stream,
                "302 Found",
                &[("location", "http://169.254.169.254/")],
                b"",
            )
            .await
        }
        "/missing" => respond(&mut stream, "404 Not Found", &[json], b"{}").await,
        "/error" => respond(&mut stream, "500 Internal Server Error", &[json], b"{}").await,
        "/created" => respond(&mut stream, "201 Created", &[json], b"{}").await,
        "/html" => {
            respond(
                &mut stream,
                "200 OK",
                &[("content-type", "text/html")],
                b"<html></html>",
            )
            .await
        }
        "/no-type" => respond(&mut stream, "200 OK", &[], b"{}").await,
        "/large-declared" => {
            let body = json!({ "padding": "x".repeat(4096) }).to_string();
            respond(&mut stream, "200 OK", &[json], body.as_bytes()).await;
        }
        "/large-chunked" => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n")
                .await;
            let first = b"{\"padding\":\"";
            let _ = stream
                .write_all(format!("{:x}\r\n", first.len()).as_bytes())
                .await;
            let _ = stream.write_all(first).await;
            let _ = stream.write_all(b"\r\n").await;
            for _ in 0..200 {
                let piece = "x".repeat(512);
                if stream
                    .write_all(format!("{:x}\r\n{piece}\r\n", piece.len()).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        "/slow" => {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            respond(&mut stream, "200 OK", &[json], b"{}").await;
        }
        "/bad-json" => respond(&mut stream, "200 OK", &[json], br#"{"keys":"#).await,
        "/post-500" => {
            let body = json!({ "error": "x".repeat(200) }).to_string();
            respond(
                &mut stream,
                "500 Internal Server Error",
                &[json],
                body.as_bytes(),
            )
            .await;
        }
        "/small" => respond(&mut stream, "200 OK", &[json], br#"{"ok":true}"#).await,
        "/large" => {
            respond(
                &mut stream,
                "200 OK",
                &[json],
                "y".repeat(64 * 1024).as_bytes(),
            )
            .await
        }
        "/exact" => respond(&mut stream, "200 OK", &[json], "z".repeat(1024).as_bytes()).await,
        _ => respond(&mut stream, "404 Not Found", &[], b"").await,
    }
}

#[tokio::test]
async fn fetches_json_from_a_loopback_server_with_allow_insecure_localhost() {
    let base = server().await;
    assert_eq!(
        fetch_json_safely(&format!("{base}/ok"), &LOCAL)
            .await
            .unwrap(),
        json!({ "keys": [{ "kid": "a" }] })
    );
    assert_eq!(
        fetch_json_safely(&format!("{base}/jwk-set"), &LOCAL)
            .await
            .unwrap(),
        json!({ "keys": [] })
    );
}

#[tokio::test]
async fn resolves_localhost_through_the_guarded_lookup() {
    let base = server().await;
    let port = base.rsplit(':').next().unwrap();
    let result = fetch_json_safely(&format!("http://localhost:{port}/ok"), &LOCAL).await;
    // localhost may resolve to ::1 first, where nothing listens; the IPv4 address is tried next.
    assert_eq!(result.unwrap(), json!({ "keys": [{ "kid": "a" }] }));
}

#[tokio::test]
async fn refuses_the_loopback_server_without_the_dev_option() {
    let base = server().await;
    assert_eq!(
        reason(fetch_json_safely(&format!("{base}/ok"), &STRICT).await),
        SafeFetchFailureReason::Url
    );
    assert_eq!(
        reason(fetch_json_safely("https://localhost/ok", &STRICT).await),
        SafeFetchFailureReason::Address
    );
}

#[tokio::test]
async fn refuses_bad_responses() {
    use SafeFetchFailureReason::*;
    let base = server().await;
    for (path, expected) in [
        ("/redirect", Redirect),
        ("/missing", Status),
        ("/error", Status),
        ("/created", Status),
        ("/html", ContentType),
        ("/no-type", ContentType),
        ("/large-declared", Size),
        ("/large-chunked", Size),
        ("/bad-json", Json),
    ] {
        assert_eq!(
            reason(fetch_json_safely(&format!("{base}{path}"), &LOCAL).await),
            expected,
            "{path}"
        );
    }
}

#[tokio::test]
async fn gives_up_at_the_deadline() {
    let base = server().await;
    let started = Instant::now();
    let options = SafeFetchOptions {
        timeout_ms: 200,
        ..LOCAL
    };
    assert_eq!(
        reason(fetch_json_safely(&format!("{base}/slow"), &options).await),
        SafeFetchFailureReason::Timeout
    );
    assert!(started.elapsed() < Duration::from_millis(1500));
}

#[tokio::test]
async fn reports_a_refused_connection_as_a_network_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    assert_eq!(
        reason(
            fetch_json_safely(
                &format!("http://127.0.0.1:{port}/ok"),
                &SafeFetchOptions {
                    timeout_ms: 10_000,
                    ..LOCAL
                }
            )
            .await
        ),
        SafeFetchFailureReason::Network
    );
}

#[tokio::test]
async fn lets_callers_cancel_bounded_bodies() {
    let base = server().await;
    for max_bytes in [None, Some(65_536)] {
        let guarded = create_guarded_fetch(GuardedFetchOptions {
            allow_insecure_localhost: true,
            any_port: true,
            max_bytes,
            ..Default::default()
        });
        for _ in 0..10 {
            let mut response = guarded
                .fetch(
                    FetchRequest::new(
                        format!("{base}/post-500"),
                        "POST",
                        Some(FetchBody::Text("{}".to_owned())),
                    )
                    .redirect(RedirectMode::Error),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 500);
            response.body.cancel();
        }
    }
}

#[tokio::test]
async fn still_reads_whole_bodies_within_the_bound_and_refuses_larger_ones() {
    let base = server().await;
    let guarded = create_guarded_fetch(GuardedFetchOptions {
        allow_insecure_localhost: true,
        any_port: true,
        max_bytes: Some(1024),
        ..Default::default()
    });
    let mut small = guarded
        .fetch(FetchRequest::get(format!("{base}/small")))
        .await
        .unwrap();
    assert_eq!(small.body.json().await.unwrap(), json!({ "ok": true }));
    // A declared length over the bound fails the request itself.
    let large = guarded
        .fetch(FetchRequest::get(format!("{base}/large")))
        .await;
    assert!(large.is_err());
    let mut exact = guarded
        .fetch(FetchRequest::get(format!("{base}/exact")))
        .await
        .unwrap();
    assert_eq!(exact.body.text().await.unwrap().len(), 1024);
    // Redirects are refused with redirect: 'error' and private addresses never connect.
    let refused = guarded
        .fetch(FetchRequest::get(format!("{base}/redirect")).redirect(RedirectMode::Error))
        .await
        .unwrap_err();
    assert_eq!(
        refused.refusal().map(|error| error.reason),
        Some(SafeFetchFailureReason::Redirect)
    );
    let manual = guarded
        .fetch(FetchRequest::get(format!("{base}/redirect")))
        .await
        .unwrap();
    assert_eq!(manual.status, 302);
    let private = guarded
        .fetch(FetchRequest::get("https://10.0.0.1/"))
        .await
        .unwrap_err();
    assert_eq!(
        private.refusal().map(|error| error.reason),
        Some(SafeFetchFailureReason::Address)
    );
}
