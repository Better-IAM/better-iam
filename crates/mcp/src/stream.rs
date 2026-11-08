//! `filterList`: removes hidden tools from a `tools/list` result, in a JSON body or an event stream.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;

use better_iam_core::{IamError, IamResult};
use bytes::Bytes;
use http::Response;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};
use serde_json::Value;

use crate::{BoxError, GateBody, McpAuthorizer, McpCaller, boxed, full, header_value};

/// A streaming UTF-8 decoder with the `TextDecoder` behaviour: a leading byte order mark is dropped, malformed
/// sequences become U+FFFD, and a sequence cut at a chunk boundary waits for the next chunk.
#[derive(Debug, Default, Clone)]
pub struct Utf8Decoder {
    pending: Vec<u8>,
    started: bool,
}

impl Utf8Decoder {
    /// Decodes the next chunk; `last` flushes an incomplete trailing sequence as U+FFFD.
    pub fn decode(&mut self, bytes: &[u8], last: bool) -> String {
        self.pending.extend_from_slice(bytes);
        let mut out = String::new();
        let mut position = 0;
        loop {
            match std::str::from_utf8(&self.pending[position..]) {
                Ok(text) => {
                    out.push_str(text);
                    position = self.pending.len();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    out.push_str(
                        std::str::from_utf8(&self.pending[position..position + valid])
                            .unwrap_or_default(),
                    );
                    position += valid;
                    match error.error_len() {
                        Some(length) => {
                            out.push('\u{fffd}');
                            position += length;
                        }
                        None => {
                            if last {
                                out.push('\u{fffd}');
                                position = self.pending.len();
                            }
                            break;
                        }
                    }
                }
            }
        }
        self.pending.drain(..position);
        if !self.started && !out.is_empty() {
            self.started = true;
            if let Some(rest) = out.strip_prefix('\u{feff}') {
                out = rest.to_owned();
            }
        }
        out
    }
}

/// `/\r?\n\r?\n/.exec(buffer)`: the first event boundary, as (index, length).
fn boundary(buffer: &str) -> Option<(usize, usize)> {
    let bytes = buffer.as_bytes();
    for start in 0..bytes.len() {
        let after_first = if bytes[start] == b'\r' && bytes.get(start + 1) == Some(&b'\n') {
            start + 2
        } else if bytes[start] == b'\n' {
            start + 1
        } else {
            continue;
        };
        let end = if bytes.get(after_first) == Some(&b'\r')
            && bytes.get(after_first + 1) == Some(&b'\n')
        {
            after_first + 2
        } else if bytes.get(after_first) == Some(&b'\n') {
            after_first + 1
        } else {
            continue;
        };
        return Some((start, end - start));
    }
    None
}

/// `text.split(/\r?\n/)`.
fn split_lines(text: &str) -> Vec<&str> {
    let pieces: Vec<&str> = text.split('\n').collect();
    let last = pieces.len() - 1;
    pieces
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            if index < last {
                piece.strip_suffix('\r').unwrap_or(piece)
            } else {
                piece
            }
        })
        .collect()
}

/// JavaScript strict equality of two optional members (`undefined` is `None`).
fn same_id(left: &Option<Value>, right: &Option<Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => better_iam_core::js::strict_equal(left, right),
        _ => false,
    }
}

/// The rewritten payload of a `tools/list` result for `id`, or `None` when the payload is something else.
async fn rewrite(
    authorizer: &McpAuthorizer,
    caller: &McpCaller,
    id: &Option<Value>,
    payload: &str,
) -> IamResult<Option<String>> {
    let Ok(message) = better_iam_core::js::parse(payload) else {
        return Ok(None);
    };
    if message.is_null() {
        return Err(IamError::with_status(
            "INTERNAL_ERROR",
            "Cannot read properties of null (reading 'id')",
            500,
        ));
    }
    let Value::Object(mut object) = message else {
        return Ok(None);
    };
    if !same_id(&object.get("id").cloned(), id) {
        return Ok(None);
    }
    let Some(Value::Object(mut result)) = object.get("result").cloned() else {
        return Ok(None);
    };
    let Some(Value::Array(tools)) = result.get("tools").cloned() else {
        return Ok(None);
    };
    let tools: Vec<Value> = tools
        .into_iter()
        .filter(|tool| tool.get("name").is_some_and(Value::is_string))
        .collect();
    let visible = authorizer.visible_tools(caller, tools).await?;
    result.insert("tools".into(), Value::Array(visible));
    object.insert("result".into(), Value::Object(result));
    Ok(Some(better_iam_core::js::stringify_object(&object)))
}

/// One event of the stream, rewritten when its data is the `tools/list` result.
async fn emit(
    authorizer: &McpAuthorizer,
    caller: &McpCaller,
    id: &Option<Value>,
    event: &str,
) -> IamResult<Bytes> {
    let lines = split_lines(event);
    let data: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect();
    let rewritten = if data.is_empty() {
        None
    } else {
        rewrite(authorizer, caller, id, &data.join("\n")).await?
    };
    let out = match rewritten {
        Some(rewritten) => {
            let mut kept: Vec<String> = lines
                .iter()
                .filter(|line| !line.starts_with("data:"))
                .map(|line| (*line).to_owned())
                .collect();
            kept.push(format!("data: {rewritten}"));
            kept.join("\n")
        }
        None => event.to_owned(),
    };
    Ok(Bytes::from(format!("{out}\n\n")))
}

fn internal(error: BoxError) -> IamError {
    IamError::with_status("INTERNAL_ERROR", error.to_string(), 500)
}

struct EventState<RB> {
    body: Pin<Box<RB>>,
    decoder: Utf8Decoder,
    buffer: String,
    out: VecDeque<Bytes>,
    done: bool,
    authorizer: Arc<McpAuthorizer>,
    caller: McpCaller,
    id: Option<Value>,
}

/// Removes hidden tools from a `tools/list` result for `id`, in a JSON body or an event stream.
pub(crate) async fn filter_list<RB>(
    authorizer: Arc<McpAuthorizer>,
    response: Response<RB>,
    id: Option<Value>,
    caller: McpCaller,
) -> IamResult<Response<GateBody>>
where
    RB: Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    let content_type = header_value(response.headers(), CONTENT_TYPE.as_str()).unwrap_or_default();
    if content_type.contains("application/json") {
        let (mut parts, body) = response.into_parts();
        parts.headers.remove(CONTENT_LENGTH);
        let bytes = body
            .collect()
            .await
            .map_err(|error| internal(error.into()))?
            .to_bytes();
        let text = Utf8Decoder::default().decode(&bytes, true);
        let body = rewrite(&authorizer, &caller, &id, &text)
            .await?
            .unwrap_or(text);
        return Ok(Response::from_parts(parts, full(body)));
    }
    if !content_type.contains("text/event-stream") {
        return Ok(response.map(boxed));
    }
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    let state = EventState {
        body: Box::pin(body),
        decoder: Utf8Decoder::default(),
        buffer: String::new(),
        out: VecDeque::new(),
        done: false,
        authorizer,
        caller,
        id,
    };
    let stream = futures::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(chunk) = state.out.pop_front() {
                return Some((Ok::<_, BoxError>(Frame::data(chunk)), state));
            }
            if state.done {
                return None;
            }
            let next: Option<Result<Frame<Bytes>, BoxError>> = state
                .body
                .as_mut()
                .frame()
                .await
                .map(|frame| frame.map_err(Into::into));
            match next {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let text = state.decoder.decode(&data, false);
                    state.buffer.push_str(&text);
                    while let Some((index, length)) = boundary(&state.buffer) {
                        let event = state.buffer[..index].to_owned();
                        state.buffer = state.buffer[index + length..].to_owned();
                        match emit(&state.authorizer, &state.caller, &state.id, &event).await {
                            Ok(chunk) => state.out.push_back(chunk),
                            Err(error) => {
                                state.done = true;
                                return Some((Err(Box::new(error) as BoxError), state));
                            }
                        }
                    }
                }
                Some(Err(error)) => {
                    state.done = true;
                    return Some((Err(error), state));
                }
                None => {
                    let rest = state.decoder.decode(&[], true);
                    state.buffer.push_str(&rest);
                    state.done = true;
                    if !better_iam_core::js::trim(&state.buffer).is_empty() {
                        let event = state
                            .buffer
                            .trim_end_matches(better_iam_core::js::is_js_whitespace)
                            .to_owned();
                        match emit(&state.authorizer, &state.caller, &state.id, &event).await {
                            Ok(chunk) => state.out.push_back(chunk),
                            Err(error) => {
                                return Some((Err(Box::new(error) as BoxError), state));
                            }
                        }
                    }
                }
            }
        }
    });
    Ok(Response::from_parts(
        parts,
        StreamBody::new(stream).boxed_unsync(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{Utf8Decoder, boundary, split_lines};

    #[test]
    fn decodes_split_sequences_and_drops_the_bom() {
        let mut decoder = Utf8Decoder::default();
        let bytes = "\u{feff}é€".as_bytes();
        let mut out = decoder.decode(&bytes[..4], false);
        out.push_str(&decoder.decode(&bytes[4..], false));
        out.push_str(&decoder.decode(&[], true));
        assert_eq!(out, "é€");
        let mut broken = Utf8Decoder::default();
        assert_eq!(
            broken.decode(&[b'a', 0xff, b'b', 0xe2, 0x82], true),
            "a\u{fffd}b\u{fffd}"
        );
    }

    #[test]
    fn finds_event_boundaries_and_lines() {
        assert_eq!(boundary("a\n\nb"), Some((1, 2)));
        assert_eq!(boundary("a\r\n\r\nb"), Some((1, 4)));
        assert_eq!(boundary("a\n\r\nb"), Some((1, 3)));
        assert_eq!(boundary("a\r\nb"), None);
        assert_eq!(split_lines("a\r\nb\nc\r"), vec!["a", "b", "c\r"]);
    }
}
