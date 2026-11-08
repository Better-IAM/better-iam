//! How results are printed (`output.ts`): `--format json|compact|table` and `--query` paths.

use std::sync::LazyLock;

use better_iam_core::js;
use regex::Regex;
use serde_json::Value;

use crate::errors::{CliResult, usage_error};

/// How a command prints its result: `json` (indented, the default), `compact` (one line), or `table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Compact,
    Table,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "compact" => Some(Self::Compact),
            "table" => Some(Self::Table),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Compact => "compact",
            Self::Table => "table",
        }
    }
}

/// `outputFormats`.
pub const OUTPUT_FORMATS: [&str; 3] = ["json", "compact", "table"];

const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// `JSON.stringify(value, null, indent)`: JavaScript number formatting, integer-like keys first, and the same
/// escaping as `JSON.stringify`.
pub fn stringify(value: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_value(value, indent, 0, &mut out);
    out
}

fn write_value(value: &Value, indent: Option<usize>, depth: usize, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            let number = js::number_value(number);
            if number.is_finite() {
                out.push_str(&js::number_to_string(number));
            } else {
                out.push_str("null");
            }
        }
        Value::String(text) => js::quote_into(text, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(indent, depth + 1, out);
                write_value(item, indent, depth + 1, out);
            }
            newline(indent, depth, out);
            out.push(']');
        }
        Value::Object(map) => {
            let entries = js::entries(map);
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(indent, depth + 1, out);
                js::quote_into(key, out);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(item, indent, depth + 1, out);
            }
            newline(indent, depth, out);
            out.push('}');
        }
    }
}

fn newline(indent: Option<usize>, depth: usize, out: &mut String) {
    if let Some(width) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(width * depth));
    }
}

static PIECE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^\[\]]*)((?:\[[0-9]*\])*)$").expect("regex"));
static INDEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[[0-9]*\]").expect("regex"));
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").expect("regex"));

/// Splits `a.b[0].c` / `items[].id` into segments; `[]` maps the rest of the path over an array.
fn segments(path: &str) -> CliResult<Vec<String>> {
    let mut parts: Vec<String> = Vec::new();
    for piece in path.split('.') {
        let Some(captures) = PIECE.captures(piece) else {
            return Err(usage_error(
                format!("--query {path} is not a path like findings[].kind or roles.0.name"),
                None,
            ));
        };
        let head = captures.get(1).map_or("", |m| m.as_str());
        if !head.is_empty() {
            parts.push(head.to_owned());
        }
        let indexes = captures.get(2).map_or("", |m| m.as_str());
        for index in INDEX.find_iter(indexes) {
            let inner = &index.as_str()[1..index.as_str().len() - 1];
            parts.push(if inner.is_empty() {
                "[]".to_owned()
            } else {
                inner.to_owned()
            });
        }
    }
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| UNSAFE_KEYS.contains(&part.as_str()))
    {
        return Err(usage_error(
            format!("--query {path} is not a usable path"),
            None,
        ));
    }
    Ok(parts)
}

/// Selects part of a result for `--query`: dotted keys (`summary.create`), array indexes (`roles.0` or `roles[0]`),
/// and `[]` to map over an array (`findings[].kind`). A missing key selects `null` rather than failing, like `jq`
/// (`selectPath`).
pub fn select_path(value: &Value, path: &str) -> CliResult<Value> {
    fn walk(current: &Value, parts: &[String]) -> Value {
        let Some((head, rest)) = parts.split_first() else {
            return current.clone();
        };
        if head == "[]" {
            return match current {
                Value::Array(items) => {
                    Value::Array(items.iter().map(|item| walk(item, rest)).collect())
                }
                _ => Value::Null,
            };
        }
        match current {
            Value::Array(items) => {
                if DIGITS.is_match(head) {
                    let item = head
                        .parse::<usize>()
                        .ok()
                        .and_then(|index| items.get(index))
                        .cloned()
                        .unwrap_or(Value::Null);
                    return walk(&item, rest);
                }
                if head == "length" {
                    return walk(&Value::from(items.len()), rest);
                }
                Value::Null
            }
            Value::Object(map) => match map.get(head.as_str()) {
                Some(item) => walk(item, rest),
                None => Value::Null,
            },
            _ => Value::Null,
        }
    }
    Ok(walk(value, &segments(path)?))
}

/// Server data printed as text (names, descriptions) may carry terminal control sequences (escape codes that rewrite
/// the screen or set the clipboard): they are shown as U+FFFD. Line breaks and tabs survive only where `keep_lines`.
fn printable(text: &str, keep_lines: bool) -> String {
    text.chars()
        .map(|c| {
            let code = c as u32;
            let control = code <= 0x1f || (0x7f..=0x9f).contains(&code);
            let kept = keep_lines && (c == '\t' || c == '\n');
            if control && !kept { '\u{FFFD}' } else { c }
        })
        .collect()
}

/// `text.length` (UTF-16 code units).
fn width_of(text: &str) -> usize {
    js::utf16_len(text)
}

/// `text.padEnd(width)`.
fn pad_end(text: &str, width: usize) -> String {
    let length = width_of(text);
    if length >= width {
        text.to_owned()
    } else {
        format!("{text}{}", " ".repeat(width - length))
    }
}

/// `text.slice(0, count)` by UTF-16 code units.
fn slice_utf16(text: &str, count: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().take(count).collect();
    String::from_utf16_lossy(&units)
}

fn cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => printable(text, false),
        Some(Value::Number(_) | Value::Bool(_)) => stringify(value.unwrap_or(&Value::Null), None),
        Some(other) => {
            let text = stringify(other, None);
            if width_of(&text) > 60 {
                format!("{}...", slice_utf16(&text, 57))
            } else {
                text
            }
        }
    }
}

/// The rows a table shows: an array as it is, or the one array inside a result object (`{ findings: [...] }`).
fn table_rows(value: &Value) -> Option<&Vec<Value>> {
    match value {
        Value::Array(items) => Some(items),
        Value::Object(map) => {
            let arrays: Vec<&Vec<Value>> = js::entries(map)
                .into_iter()
                .filter_map(|(_, item)| item.as_array())
                .collect();
            if arrays.len() == 1 {
                Some(arrays[0])
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Renders rows of objects as aligned columns (keys in first-seen order), or an object as key/value lines
/// (`renderTable`).
pub fn render_table(value: &Value) -> String {
    let Some(rows) = table_rows(value) else {
        if let Value::Object(map) = value {
            let entries = js::entries(map);
            let width = entries
                .iter()
                .map(|(key, _)| width_of(key))
                .max()
                .unwrap_or(0);
            return entries
                .into_iter()
                .map(|(key, item)| {
                    format!(
                        "{}  {}",
                        pad_end(&printable(key, false), width),
                        cell(Some(item))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        return cell(Some(value));
    };
    if rows.is_empty() {
        return "(no rows)".to_owned();
    }
    if rows.iter().all(|row| !row.is_object()) {
        return rows
            .iter()
            .map(|row| cell(Some(row)))
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut columns: Vec<String> = Vec::new();
    for row in rows {
        if let Value::Object(map) = row {
            for key in js::keys(map) {
                if !columns.contains(key) {
                    columns.push(key.clone());
                }
            }
        }
    }
    let shown: Vec<&String> = columns.iter().take(8).collect();
    let mut grid: Vec<Vec<String>> = vec![
        shown
            .iter()
            .map(|column| printable(column, false).to_uppercase())
            .collect(),
    ];
    for row in rows {
        grid.push(
            shown
                .iter()
                .map(|column| cell(row.as_object().and_then(|map| map.get(column.as_str()))))
                .collect(),
        );
    }
    let widths: Vec<usize> = (0..shown.len())
        .map(|index| {
            grid.iter()
                .map(|line| width_of(&line[index]))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut lines: Vec<String> = grid
        .iter()
        .map(|line| {
            line.iter()
                .enumerate()
                .map(|(index, text)| {
                    if index == line.len() - 1 {
                        text.clone()
                    } else {
                        pad_end(text, widths[index])
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_owned()
        })
        .collect();
    if columns.len() > shown.len() {
        lines.push(format!(
            "({} more column(s); use --format json to see them)",
            columns.len() - shown.len()
        ));
    }
    lines.join("\n")
}

/// Turns a command result into the text printed on stdout. Strings are printed as they are (`formatResult`).
pub fn format_result(
    value: &Value,
    format: Option<OutputFormat>,
    query: Option<&str>,
) -> CliResult<String> {
    let selected = match query {
        None => value.clone(),
        Some(path) => select_path(value, path)?,
    };
    if let Value::String(text) = &selected {
        return Ok(printable(text, true));
    }
    Ok(match format.unwrap_or(OutputFormat::Json) {
        OutputFormat::Table => render_table(&selected),
        OutputFormat::Compact => stringify(&selected, None),
        OutputFormat::Json => stringify(&selected, Some(2)),
    })
}
