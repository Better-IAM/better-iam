//! The HTTP plumbing of the provider: request parameters (`querystring.parse` semantics), signed cookies (Koa
//! `cookies` with keygrip), responses, and the HTML helpers of `oidc-provider`.

use better_iam_core::js;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use sha1::Sha1;

use crate::resource_server::{HttpRequest, HttpResponse};

/// A parsed parameter: one value, or several when the name repeats (`querystring.parse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    One(String),
    Many(Vec<String>),
}

impl Param {
    pub fn to_value(&self) -> Value {
        match self {
            Param::One(value) => Value::String(value.clone()),
            Param::Many(values) => {
                Value::Array(values.iter().cloned().map(Value::String).collect())
            }
        }
    }

    pub fn from_value(value: &Value) -> Option<Param> {
        match value {
            Value::String(text) => Some(Param::One(text.clone())),
            Value::Array(values) => Some(Param::Many(
                values
                    .iter()
                    .map(|value| match value {
                        Value::String(text) => text.clone(),
                        other => js::stringify(other),
                    })
                    .collect(),
            )),
            Value::Null => None,
            other => Some(Param::One(match other {
                Value::Bool(value) => value.to_string(),
                Value::Number(number) => js::number_to_string(number.as_f64().unwrap_or_default()),
                other => js::stringify(other),
            })),
        }
    }
}

/// Parameters by name, in first-seen order.
pub type RawParams = IndexMap<String, Param>;

/// `querystring.parse(text)`: `+` is a space, repeated names collect into arrays, malformed escapes stay as they are.
pub fn parse_query(text: &str) -> RawParams {
    let mut out: RawParams = IndexMap::new();
    if text.is_empty() {
        return out;
    }
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.find('=') {
            Some(index) => (&pair[..index], &pair[index + 1..]),
            None => (pair, ""),
        };
        let key = unescape(key);
        let value = unescape(value);
        match out.get_mut(&key) {
            Some(Param::One(existing)) => {
                let first = std::mem::take(existing);
                out.insert(key, Param::Many(vec![first, value]));
            }
            Some(Param::Many(values)) => values.push(value),
            None => {
                out.insert(key, Param::One(value));
            }
        }
    }
    out
}

/// `querystring.unescape`: `+` as space, percent escapes decoded leniently.
fn unescape(value: &str) -> String {
    let replaced = value.replace('+', " ");
    let bytes = replaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(hex) = replaced.get(index + 1..index + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Params(allowList, source)`: each allowed name with its value, falsy values (empty strings) as absent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Params {
    pub values: IndexMap<String, Option<Param>>,
}

impl Params {
    pub fn new(allow: &[&str], source: &RawParams) -> Self {
        let mut values = IndexMap::new();
        for name in allow {
            let value = source.get(*name).cloned().filter(|value| match value {
                Param::One(text) => !text.is_empty(),
                Param::Many(_) => true,
            });
            values.insert((*name).to_owned(), value);
        }
        Self { values }
    }

    /// A single string value (None when absent or repeated).
    pub fn get(&self, name: &str) -> Option<&str> {
        match self.values.get(name) {
            Some(Some(Param::One(value))) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn raw(&self, name: &str) -> Option<&Param> {
        self.values.get(name).and_then(Option::as_ref)
    }

    pub fn has(&self, name: &str) -> bool {
        self.raw(name).is_some()
    }

    pub fn is_allowed(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    pub fn set(&mut self, name: &str, value: Option<String>) {
        self.values.insert(
            name.to_owned(),
            value.filter(|v| !v.is_empty()).map(Param::One),
        );
    }

    pub fn set_raw(&mut self, name: &str, value: Option<Param>) {
        self.values.insert(name.to_owned(), value);
    }

    pub fn remove(&mut self, name: &str) {
        if let Some(slot) = self.values.get_mut(name) {
            *slot = None;
        }
    }

    /// `toPlainObject()`.
    pub fn to_plain(&self) -> Map<String, Value> {
        self.values
            .iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| (key.clone(), value.to_value())))
            .collect()
    }

    /// `rejectDupes({ except, only })`: names given twice, cleared.
    pub fn reject_dupes(&mut self, except: &[&str], only: Option<&[&str]>) -> Vec<String> {
        let mut dupes = Vec::new();
        for (key, value) in self.values.iter_mut() {
            if !matches!(value, Some(Param::Many(_))) {
                continue;
            }
            if except.contains(&key.as_str()) {
                continue;
            }
            if let Some(only) = only
                && !only.contains(&key.as_str())
            {
                continue;
            }
            dupes.push(key.clone());
            *value = None;
        }
        dupes
    }
}

/// `formatList(list)` (conjunction): `'a'`, `'a' and 'b'`, `'a', 'b', and 'c'`.
pub fn format_list(items: &[String], disjunction: bool) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("'{item}'")).collect();
    let word = if disjunction { "or" } else { "and" };
    match quoted.len() {
        0 => String::new(),
        1 => quoted[0].clone(),
        2 => format!("{} {word} {}", quoted[0], quoted[1]),
        _ => {
            let (last, rest) = quoted.split_last().expect("non-empty");
            format!("{}, {word} {last}", rest.join(", "))
        }
    }
}

pub fn pluralize(word: &str, count: usize) -> String {
    if count == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

/// `htmlSafe(input)`.
pub fn html_safe(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Keygrip signatures (HMAC-SHA1, URL-safe base64 without padding) over `name=value`.
#[derive(Debug, Clone)]
pub struct Keygrip {
    keys: Vec<String>,
}

impl Keygrip {
    pub fn new(keys: Vec<String>) -> Self {
        Self { keys }
    }

    fn sign_with(key: &str, data: &str) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).expect("any key length");
        mac.update(data.as_bytes());
        let digest = mac.finalize().into_bytes();
        crate::jose::b64(&digest)
            .replace('/', "_")
            .replace('+', "-")
            .trim_end_matches('=')
            .to_owned()
    }

    pub fn sign(&self, data: &str) -> String {
        Self::sign_with(
            self.keys.first().map(String::as_str).unwrap_or_default(),
            data,
        )
    }

    /// The index of the key that produced `digest`, if any.
    pub fn index(&self, data: &str, digest: &str) -> Option<usize> {
        self.keys
            .iter()
            .position(|key| crate::jose::constant_equals(&Self::sign_with(key, data), digest))
    }
}

/// Cookie options (`cookies.long` / `cookies.short`).
#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    pub path: Option<String>,
    pub max_age_ms: Option<f64>,
    pub expires: Option<f64>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site_lax: bool,
}

fn http_date(ms: f64) -> String {
    // `new Date(ms).toUTCString()`: `Thu, 01 Jan 1970 00:00:00 GMT`.
    let seconds = (ms / 1000.0).floor() as i64;
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let (year, month, day) = js::civil_from_days(days);
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        months[(month - 1).clamp(0, 11) as usize],
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Serializes one cookie as the `cookies` package does.
pub fn serialize_cookie(name: &str, value: Option<&str>, options: &CookieOptions) -> String {
    let mut out = format!("{name}={}", value.unwrap_or_default());
    out.push_str(&format!(
        "; path={}",
        options.path.as_deref().unwrap_or("/")
    ));
    let expires = if value.is_none() {
        Some(0.0)
    } else if let Some(max_age) = options.max_age_ms {
        Some(js::now_ms() + max_age)
    } else {
        options.expires
    };
    if let Some(expires) = expires {
        out.push_str(&format!("; expires={}", http_date(expires)));
    }
    if options.same_site_lax {
        out.push_str("; samesite=lax");
    }
    if options.secure {
        out.push_str("; secure");
    }
    if options.http_only {
        out.push_str("; httponly");
    }
    out
}

/// The cookies of a request.
pub fn request_cookies(request: &HttpRequest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for header in request.headers().get_all("cookie") {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for part in text.split(';') {
            let part = part.trim();
            if let Some(index) = part.find('=') {
                out.push((
                    part[..index].trim().to_owned(),
                    part[index + 1..].trim().to_owned(),
                ));
            }
        }
    }
    out
}

/// A signed cookie value (`cookies.get(name, { signed: true })`).
pub fn get_signed_cookie(
    cookies: &[(String, String)],
    keygrip: &Keygrip,
    name: &str,
) -> Option<String> {
    let value = cookies
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())?;
    let signature = cookies
        .iter()
        .find(|(key, _)| *key == format!("{name}.sig"))
        .map(|(_, value)| value.clone())?;
    keygrip
        .index(&format!("{name}={value}"), &signature)
        .map(|_| value)
}

/// A response under construction.
#[derive(Debug, Clone, Default)]
pub struct Out {
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    pub content_type: Option<String>,
}

impl Out {
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let name = name.to_ascii_lowercase();
        self.headers.retain(|(key, _)| *key != name);
        self.headers.push((name, value.into()));
    }

    pub fn append(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
    }

    pub fn remove(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.headers.retain(|(key, _)| *key != name);
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.headers.iter().any(|(key, _)| key.starts_with(prefix))
    }

    /// `ctx.vary(field)`.
    pub fn vary(&mut self, field: &str) {
        match self.get("vary").map(str::to_owned) {
            Some(existing) => {
                if !existing
                    .split(',')
                    .any(|value| value.trim().eq_ignore_ascii_case(field))
                {
                    self.set("vary", format!("{existing}, {field}"));
                }
            }
            None => self.set("vary", field),
        }
    }

    pub fn json(&mut self, value: &Value) {
        self.content_type = Some("application/json; charset=utf-8".into());
        self.body = Some(Bytes::from(js::stringify(value)));
    }

    pub fn html(&mut self, html: String) {
        self.content_type = Some("text/html; charset=utf-8".into());
        self.body = Some(Bytes::from(html));
    }

    pub fn text(&mut self, text: &str) {
        self.content_type = Some("text/plain; charset=utf-8".into());
        self.body = Some(Bytes::from(text.to_owned()));
    }

    /// `ctx.redirect(url)` with the status already chosen (303 unless set).
    pub fn redirect(&mut self, url: &str) {
        self.set("location", url);
        if !matches!(self.status, Some(300..=399)) {
            self.status = Some(302);
        }
        self.content_type = Some("text/html; charset=utf-8".into());
        self.body = Some(Bytes::from(format!(
            "Redirecting to <a href=\"{}\">{}</a>.",
            html_safe(url),
            html_safe(url)
        )));
    }

    /// The final response (Koa: 204 for an empty body with no status, 404 when nothing answered).
    pub fn finish(self) -> HttpResponse {
        let status = match (self.status, &self.body) {
            (Some(status), _) => status,
            (None, Some(_)) => 200,
            (None, None) => 404,
        };
        let mut builder = http::Response::builder().status(status);
        let mut has_type = false;
        for (name, value) in &self.headers {
            if name == "content-type" {
                has_type = true;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        let body = match (status, self.body) {
            (204 | 304, _) => Bytes::new(),
            (_, Some(body)) => {
                if !has_type && let Some(content_type) = &self.content_type {
                    builder = builder.header("content-type", content_type.as_str());
                }
                builder = builder.header("content-length", body.len().to_string());
                body
            }
            (404, None) => {
                builder = builder
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("content-length", "9");
                Bytes::from_static(b"Not Found")
            }
            (_, None) => Bytes::new(),
        };
        builder.body(body).unwrap_or_else(|_| {
            let mut fallback = http::Response::new(Bytes::new());
            *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
    }
}

/// `formPost(ctx, action, inputs)`: an auto-submitting form.
pub fn form_post(out: &mut Out, action: &str, inputs: &[(&str, String)]) {
    if !matches!(out.status, Some(200 | 400 | 500)) {
        out.status = Some(if inputs.iter().any(|(key, _)| *key == "error") {
            400
        } else {
            200
        });
    }
    let form_inputs: Vec<String> = inputs
        .iter()
        .map(|(key, value)| {
            format!(
                "<input type=\"hidden\" name=\"{key}\" value=\"{}\"/>",
                html_safe(value)
            )
        })
        .collect();
    let script = "\n    document.addEventListener('DOMContentLoaded', function () { document.forms[0].submit() });\n  ";
    out.html(format!(
        "<!DOCTYPE html>\n<html>\n<head>\n  <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n  <title>Submitting Callback</title>\n  <script>{script}</script>\n</head>\n<body>\n  <form method=\"post\" action=\"{}\">\n    {}\n    <noscript>\n      Your browser does not support JavaScript or you've disabled it.<br/>\n      <button autofocus type=\"submit\">Continue</button>\n    </noscript>\n  </form>\n</body>\n</html>",
        html_safe(action),
        form_inputs.join("\n")
    ));
}

/// `redirectUri(uri, payload, 'query')`: sets each member as a query parameter.
pub fn redirect_with_query(uri: &str, payload: &[(String, String)]) -> String {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return uri.to_owned();
    };
    let mut pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    for (key, value) in payload {
        if let Some(index) = pairs.iter().position(|(existing, _)| existing == key) {
            pairs[index].1 = value.clone();
            let mut seen = false;
            pairs.retain(|(existing, _)| {
                if existing != key {
                    return true;
                }
                let keep = !seen;
                seen = true;
                keep
            });
        } else {
            pairs.push((key.clone(), value.clone()));
        }
    }
    if pairs.is_empty() {
        parsed.set_query(None);
    } else {
        parsed.query_pairs_mut().clear().extend_pairs(pairs.iter());
    }
    parsed.to_string()
}

/// `ctx.accepts('json', 'html')` (negotiator's media type preference): true when `text/html` wins.
pub fn accepts_html(request: &HttpRequest) -> bool {
    let Some(accept) = request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    // (type, subtype, quality, order)
    let mut entries: Vec<(String, String, f64, usize)> = Vec::new();
    for (order, part) in accept.split(',').enumerate() {
        let mut pieces = part.split(';');
        let media = pieces
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let Some((kind, sub)) = media.split_once('/') else {
            continue;
        };
        let mut quality = 1.0;
        for parameter in pieces {
            if let Some(value) = parameter.trim().strip_prefix("q=") {
                quality = value.trim().parse::<f64>().unwrap_or(0.0);
            }
        }
        entries.push((
            kind.trim().to_owned(),
            sub.trim().to_owned(),
            quality,
            order,
        ));
    }
    // (quality, specificity, order, index) of each candidate.
    let priority = |kind: &str, sub: &str, index: usize| -> (f64, i32, i64, usize) {
        let mut best: (f64, i32, i64, usize) = (0.0, 0, -1, index);
        for (entry_kind, entry_sub, quality, order) in &entries {
            let mut specificity = 0;
            if entry_kind == kind {
                specificity |= 4;
            } else if entry_kind != "*" {
                continue;
            }
            if entry_sub == sub {
                specificity |= 2;
            } else if entry_sub != "*" {
                continue;
            }
            let candidate = (*quality, specificity, *order as i64, index);
            let better = (best.1 - candidate.1)
                .signum()
                .cmp(&0)
                .then_with(|| {
                    best.0
                        .partial_cmp(&candidate.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| best.2.cmp(&candidate.2));
            if better == std::cmp::Ordering::Less {
                best = candidate;
            }
        }
        best
    };
    let json = priority("application", "json", 0);
    let html = priority("text", "html", 1);
    let candidates: Vec<(f64, i32, i64, usize, bool)> = [(json, false), (html, true)]
        .into_iter()
        .filter(|((quality, _, _, _), _)| *quality > 0.0)
        .map(|((quality, specificity, order, index), is_html)| {
            (quality, specificity, order, index, is_html)
        })
        .collect();
    let winner = candidates.into_iter().min_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
    });
    winner.is_some_and(|candidate| candidate.4)
}
