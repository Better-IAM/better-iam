//! Port of `packages/server/src/client-info.ts`: the client details Better IAM records for a request.
//!
//! `http.clientInfo(request)` when the deployment supplies it (IP behind a trusted proxy, user agent, label),
//! otherwise the User-Agent header only. Nothing here is trusted for authorization; the result feeds
//! `auth.withClient`.

use better_iam_core::SessionClientInfo;
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::options::{HttpOptions, RequestHead};

/// `headers.get(name)`: repeated values joined with ", "; None when absent.
pub fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// `clientFromRequest(options, request)`.
pub fn client_from_request(
    http: Option<&HttpOptions>,
    request: &RequestHead,
) -> Option<SessionClientInfo> {
    if let Some(client_info) = http.and_then(|http| http.client_info.as_ref()) {
        return client_info(request);
    }
    let user_agent = header(&request.headers, "user-agent").filter(|agent| !agent.is_empty())?;
    Some(SessionClientInfo {
        user_agent: Some(user_agent),
        ..SessionClientInfo::default()
    })
}

/// A request head for `baseURL` with these headers (`new Request(baseURL, { headers })`); None when a header name or
/// value is not valid (the Request constructor throws).
pub fn request_head(headers: &[(String, String)], base_url: &str) -> Option<RequestHead> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
        // Header values are trimmed of leading and trailing HTTP whitespace, as the Headers class does.
        let value = HeaderValue::from_str(value.trim_matches([' ', '\t', '\n', '\r'])).ok()?;
        map.append(name, value);
    }
    let (mut parts, ()) = http::Request::builder()
        .uri(base_url)
        .body(())
        .ok()?
        .into_parts();
    parts.headers = map;
    Some(parts)
}

/// `clientFromHeaders(options, headers, baseURL)`: for callers that only have the incoming request's headers
/// (framework integrations passing `{ headers }` as the credential). None when there are no headers to read.
pub fn client_from_headers(
    http: Option<&HttpOptions>,
    headers: Option<&[(String, String)]>,
    base_url: &str,
) -> Option<SessionClientInfo> {
    let headers = headers?;
    let request = request_head(headers, base_url)?;
    client_from_request(http, &request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn default_records_the_user_agent() {
        let headers = vec![("User-Agent".to_owned(), "Browser/1".to_owned())];
        let client = client_from_headers(None, Some(&headers), "https://iam.example.com").unwrap();
        assert_eq!(client.user_agent.as_deref(), Some("Browser/1"));
        assert!(client_from_headers(None, Some(&[]), "https://iam.example.com").is_none());
        assert!(client_from_headers(None, None, "https://iam.example.com").is_none());
        let custom = HttpOptions {
            client_info: Some(Arc::new(|request: &RequestHead| {
                Some(SessionClientInfo {
                    ip: header(&request.headers, "x-real-ip"),
                    ..SessionClientInfo::default()
                })
            })),
            ..HttpOptions::default()
        };
        let headers = vec![("X-Real-IP".to_owned(), "192.0.2.1".to_owned())];
        let client =
            client_from_headers(Some(&custom), Some(&headers), "https://iam.example.com").unwrap();
        assert_eq!(client.ip.as_deref(), Some("192.0.2.1"));
    }
}
