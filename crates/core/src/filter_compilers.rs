//! Compilers for query plans (`filter-compilers.ts`): the same filter as an in-memory predicate, SQL for PostgreSQL
//! and SQLite, a Prisma `where`, and a MongoDB query. Each atom is NULL-safe (a missing field satisfies nothing but
//! `not exists`), so negations behave like the policy engine rather than like SQL's three-valued logic.

use serde_json::{Map, Value};

use crate::js;
use crate::plan::{
    CompareOperator, DateOperator, FilterType, FilterValue, GlobToken, ResourceFilter,
    glob_matches, parse_glob,
};
use crate::policy::{ip_matches, is_ip_range, parse_timestamp};
use crate::{IamError, IamResult};

fn unsupported(kind: &str, target: &str) -> IamError {
    IamError::new(
        "UNSUPPORTED_FILTER",
        format!(
            "{kind} conditions cannot be expressed in {target}; filter these resources with filterMatches or authorize"
        ),
    )
}

fn is_address(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if !text.contains('/') && is_ip_range(text))
}

fn same_value(actual: Option<&Value>, expected: &FilterValue, ignore_case: bool) -> bool {
    match (actual, expected) {
        (Some(Value::Number(actual)), FilterValue::Number(expected)) => {
            js::number_value(actual) == *expected
        }
        (Some(Value::String(actual)), FilterValue::String(expected)) => {
            if ignore_case {
                js::to_lower(actual) == js::to_lower(expected)
            } else {
                actual == expected
            }
        }
        (Some(Value::Bool(actual)), FilterValue::Bool(expected)) => actual == expected,
        _ => false,
    }
}

/// Whether a resource passes a filter (`filterMatches`): `record.id` is the id and every other field is read by
/// name. This is exact, with the policy engine's semantics, and supports every filter.
pub fn filter_matches(filter: &ResourceFilter, record: &Map<String, Value>) -> bool {
    let read = |field: &str| record.get(field);
    match filter {
        ResourceFilter::True => true,
        ResourceFilter::False => false,
        ResourceFilter::And(filters) => filters.iter().all(|item| filter_matches(item, record)),
        ResourceFilter::Or(filters) => filters.iter().any(|item| filter_matches(item, record)),
        ResourceFilter::Not(inner) => !filter_matches(inner, record),
        ResourceFilter::Exists { field } => read(field).is_some(),
        ResourceFilter::Type { field, kind } => {
            let value = read(field);
            match kind {
                FilterType::Ip => is_address(value),
                FilterType::Number => matches!(value, Some(Value::Number(_))),
                FilterType::String => matches!(value, Some(Value::String(_))),
                FilterType::Boolean => matches!(value, Some(Value::Bool(_))),
            }
        }
        ResourceFilter::Equals {
            field,
            values,
            ignore_case,
        } => {
            let value = read(field);
            values
                .iter()
                .any(|expected| same_value(value, expected, *ignore_case))
        }
        ResourceFilter::Compare {
            field,
            operator,
            value: expected,
        } => match read(field).and_then(js::as_number) {
            None => false,
            Some(value) => match operator {
                CompareOperator::Lt => value < *expected,
                CompareOperator::Le => value <= *expected,
                CompareOperator::Gt => value > *expected,
                CompareOperator::Ge => value >= *expected,
            },
        },
        ResourceFilter::Like {
            field,
            pattern,
            ignore_case,
        } => match read(field) {
            Some(Value::String(value)) => {
                if *ignore_case {
                    glob_matches(&parse_glob(&js::to_lower(pattern)), &js::to_lower(value))
                } else {
                    glob_matches(&parse_glob(pattern), value)
                }
            }
            _ => false,
        },
        ResourceFilter::Date {
            field,
            operator,
            value,
        } => {
            let left = read(field)
                .and_then(Value::as_str)
                .and_then(parse_timestamp);
            let right = parse_timestamp(value);
            match (left, right) {
                (Some(left), Some(right)) => match operator {
                    DateOperator::Before => left < right,
                    DateOperator::After => left > right,
                },
                _ => false,
            }
        }
        ResourceFilter::Ip { field, network } => match read(field) {
            Some(Value::String(value)) => ip_matches(value, network),
            _ => false,
        },
        ResourceFilter::Contains { field, value } => match read(field) {
            Some(Value::Array(items)) => js::includes(items, &value.to_value()),
            _ => false,
        },
    }
}

// --- SQL -----------------------------------------------------------------------------------------

/// `SqlFilterOptions.dialect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDialect {
    Postgres,
    Sqlite,
}

/// `SqlFilterOptions`.
pub struct SqlFilterOptions<'a> {
    pub dialect: FilterDialect,
    /// The SQL expression for a field: a trusted column name or JSON path expression of your schema. None refuses a
    /// field the plan names that your table does not have.
    pub column: &'a dyn Fn(&str) -> Option<String>,
    /// PostgreSQL placeholders start after this many parameters (default 0).
    pub offset: usize,
}

/// `SqlFilter`: a boolean SQL expression for a `WHERE` clause and its parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct SqlFilter {
    pub sql: String,
    pub params: Vec<Value>,
}

/// A glob as a SQLite GLOB pattern: wildcards stay, literal `*`, `?` and `[` become character classes.
fn sqlite_glob(pattern: &str, lower: bool) -> String {
    let source = if lower {
        js::to_lower(pattern)
    } else {
        pattern.to_owned()
    };
    parse_glob(&source)
        .into_iter()
        .map(|token| match token {
            GlobToken::Star => "*".to_owned(),
            GlobToken::Any => "?".to_owned(),
            GlobToken::Char(c @ ('*' | '?' | '[')) => format!("[{c}]"),
            GlobToken::Char(c) => c.to_string(),
        })
        .collect()
}

/// A glob as a LIKE pattern with `\` as the escape character.
fn like_pattern(pattern: &str, lower: bool) -> String {
    let source = if lower {
        js::to_lower(pattern)
    } else {
        pattern.to_owned()
    };
    parse_glob(&source)
        .into_iter()
        .map(|token| match token {
            GlobToken::Star => "%".to_owned(),
            GlobToken::Any => "_".to_owned(),
            GlobToken::Char(c @ ('%' | '_' | '\\')) => format!("\\{c}"),
            GlobToken::Char(c) => c.to_string(),
        })
        .collect()
}

fn comparison_symbol(operator: CompareOperator) -> &'static str {
    match operator {
        CompareOperator::Lt => "<",
        CompareOperator::Le => "<=",
        CompareOperator::Gt => ">",
        CompareOperator::Ge => ">=",
    }
}

/// The filter as a parameterized SQL expression (`filterToSql`). PostgreSQL uses `$n` placeholders and SQLite `?`.
/// IP and array conditions refuse with UNSUPPORTED_FILTER.
pub fn filter_to_sql(
    filter: &ResourceFilter,
    options: &SqlFilterOptions<'_>,
) -> IamResult<SqlFilter> {
    struct Compiler<'a, 'b> {
        options: &'a SqlFilterOptions<'b>,
        params: Vec<Value>,
    }
    impl Compiler<'_, '_> {
        fn postgres(&self) -> bool {
            self.options.dialect == FilterDialect::Postgres
        }
        fn bind(&mut self, value: Value) -> String {
            let value = match value {
                Value::Bool(flag) if !self.postgres() => Value::from(u8::from(flag)),
                other => other,
            };
            self.params.push(value);
            if self.postgres() {
                format!("${}", self.options.offset + self.params.len())
            } else {
                "?".to_owned()
            }
        }
        fn column(&self, field: &str) -> IamResult<String> {
            match (self.options.column)(field) {
                Some(expression) if !expression.is_empty() => Ok(expression),
                _ => Err(IamError::new(
                    "INVALID_INPUT",
                    format!("The plan filters on {field}, which has no column"),
                )),
            }
        }
        fn compile(&mut self, item: &ResourceFilter) -> IamResult<String> {
            let postgres = self.postgres();
            Ok(match item {
                ResourceFilter::True => if postgres { "TRUE" } else { "1 = 1" }.to_owned(),
                ResourceFilter::False => if postgres { "FALSE" } else { "1 = 0" }.to_owned(),
                ResourceFilter::And(filters) => {
                    let parts = filters
                        .iter()
                        .map(|filter| self.compile(filter))
                        .collect::<IamResult<Vec<_>>>()?;
                    format!("({})", parts.join(" AND "))
                }
                ResourceFilter::Or(filters) => {
                    let parts = filters
                        .iter()
                        .map(|filter| self.compile(filter))
                        .collect::<IamResult<Vec<_>>>()?;
                    format!("({})", parts.join(" OR "))
                }
                ResourceFilter::Not(inner) => format!("(NOT {})", self.compile(inner)?),
                ResourceFilter::Exists { field } => {
                    format!("({} IS NOT NULL)", self.column(field)?)
                }
                ResourceFilter::Type { field, kind } => {
                    if *kind == FilterType::Ip {
                        return Err(unsupported("IP address", "SQL"));
                    }
                    format!("({} IS NOT NULL)", self.column(field)?)
                }
                ResourceFilter::Equals {
                    field,
                    values,
                    ignore_case,
                } => {
                    let expression = self.column(field)?;
                    let target = if *ignore_case {
                        format!("LOWER({expression})")
                    } else {
                        expression.clone()
                    };
                    let placeholders: Vec<String> = values
                        .iter()
                        .map(|value| match value {
                            FilterValue::String(text) if *ignore_case => {
                                Value::String(js::to_lower(text))
                            }
                            other => other.to_value(),
                        })
                        .map(|value| self.bind(value))
                        .collect();
                    format!(
                        "({expression} IS NOT NULL AND {target} IN ({}))",
                        placeholders.join(", ")
                    )
                }
                ResourceFilter::Compare {
                    field,
                    operator,
                    value,
                } => {
                    let expression = self.column(field)?;
                    let placeholder = self.bind(js::number(*value).unwrap_or(Value::Null));
                    format!(
                        "({expression} IS NOT NULL AND {expression} {} {placeholder})",
                        comparison_symbol(*operator)
                    )
                }
                ResourceFilter::Like {
                    field,
                    pattern,
                    ignore_case,
                } => {
                    let expression = self.column(field)?;
                    let target = if *ignore_case {
                        format!("LOWER({expression})")
                    } else {
                        expression.clone()
                    };
                    let predicate = if postgres {
                        let placeholder =
                            self.bind(Value::String(like_pattern(pattern, *ignore_case)));
                        format!("{target} LIKE {placeholder} ESCAPE '\\'")
                    } else {
                        let placeholder =
                            self.bind(Value::String(sqlite_glob(pattern, *ignore_case)));
                        format!("{target} GLOB {placeholder}")
                    };
                    format!("({expression} IS NOT NULL AND {predicate})")
                }
                ResourceFilter::Date {
                    field,
                    operator,
                    value,
                } => {
                    let expression = self.column(field)?;
                    let symbol = if *operator == DateOperator::Before {
                        "<"
                    } else {
                        ">"
                    };
                    let placeholder = self.bind(Value::String(value.clone()));
                    let predicate = if postgres {
                        format!("({expression})::timestamptz {symbol} {placeholder}::timestamptz")
                    } else {
                        format!("julianday({expression}) {symbol} julianday({placeholder})")
                    };
                    format!("({expression} IS NOT NULL AND {predicate})")
                }
                ResourceFilter::Ip { .. } => return Err(unsupported("IP address", "SQL")),
                ResourceFilter::Contains { .. } => return Err(unsupported("Array", "SQL")),
            })
        }
    }
    let mut compiler = Compiler {
        options,
        params: Vec::new(),
    };
    let sql = compiler.compile(filter)?;
    Ok(SqlFilter {
        sql,
        params: compiler.params,
    })
}

// --- Prisma --------------------------------------------------------------------------------------

/// A field mapping for Prisma and MongoDB (`options.field`): the model or document field for a plan field.
pub type FieldMapping<'a> = Option<&'a dyn Fn(&str) -> String>;

fn object(entries: Vec<(String, Value)>) -> Value {
    Value::Object(entries.into_iter().collect())
}

/// A glob that Prisma's string filters can express: exact, a prefix, a suffix, or a substring.
fn simple_glob(pattern: &str) -> Option<(&'static str, String)> {
    let tokens = parse_glob(pattern);
    if tokens.contains(&GlobToken::Any) {
        return None;
    }
    let stars: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == GlobToken::Star)
        .map(|(index, _)| index)
        .collect();
    let text: String = tokens
        .iter()
        .filter_map(|token| {
            if let GlobToken::Char(c) = token {
                Some(*c)
            } else {
                None
            }
        })
        .collect();
    let last = tokens.len().wrapping_sub(1);
    if stars.is_empty() {
        return Some(("equals", text));
    }
    if stars.len() == 1 && stars[0] == last {
        return Some(("startsWith", text));
    }
    if stars.len() == 1 && stars[0] == 0 {
        return Some(("endsWith", text));
    }
    if stars.len() == 2 && stars[0] == 0 && stars[1] == last {
        return Some(("contains", text));
    }
    None
}

fn prisma_operator(operator: CompareOperator) -> &'static str {
    match operator {
        CompareOperator::Le => "lte",
        CompareOperator::Ge => "gte",
        CompareOperator::Lt => "lt",
        CompareOperator::Gt => "gt",
    }
}

/// The filter as a Prisma `where` object (`filterToPrisma`). Globs must be exact, a prefix, a suffix or a
/// substring; dates, IP addresses, and other globs refuse with UNSUPPORTED_FILTER.
pub fn filter_to_prisma(filter: &ResourceFilter, field: FieldMapping<'_>) -> IamResult<Value> {
    let name = |plan_field: &str| {
        field
            .map(|mapping| mapping(plan_field))
            .unwrap_or_else(|| plan_field.to_owned())
    };
    let present = |plan_field: &str| {
        object(vec![(
            name(plan_field),
            object(vec![("not".into(), Value::Null)]),
        )])
    };
    fn compile(
        item: &ResourceFilter,
        name: &dyn Fn(&str) -> String,
        present: &dyn Fn(&str) -> Value,
    ) -> IamResult<Value> {
        let list = |filters: &[ResourceFilter]| -> IamResult<Value> {
            Ok(Value::Array(
                filters
                    .iter()
                    .map(|filter| compile(filter, name, present))
                    .collect::<IamResult<_>>()?,
            ))
        };
        Ok(match item {
            ResourceFilter::True => object(vec![]),
            ResourceFilter::False => object(vec![(
                name("id"),
                object(vec![("in".into(), Value::Array(vec![]))]),
            )]),
            ResourceFilter::And(filters) => object(vec![("AND".into(), list(filters)?)]),
            ResourceFilter::Or(filters) => object(vec![("OR".into(), list(filters)?)]),
            ResourceFilter::Not(inner) => {
                object(vec![("NOT".into(), compile(inner, name, present)?)])
            }
            ResourceFilter::Exists { field } => present(field),
            ResourceFilter::Type { field, kind } => {
                if *kind == FilterType::Ip {
                    return Err(unsupported("IP address", "Prisma"));
                }
                present(field)
            }
            ResourceFilter::Equals {
                field,
                values,
                ignore_case,
            } => {
                let test = if *ignore_case {
                    object(vec![(
                        "OR".into(),
                        Value::Array(
                            values
                                .iter()
                                .map(|value| {
                                    object(vec![(
                                        name(field),
                                        object(vec![
                                            ("equals".into(), value.to_value()),
                                            ("mode".into(), Value::String("insensitive".into())),
                                        ]),
                                    )])
                                })
                                .collect(),
                        ),
                    )])
                } else {
                    object(vec![(
                        name(field),
                        object(vec![(
                            "in".into(),
                            Value::Array(values.iter().map(FilterValue::to_value).collect()),
                        )]),
                    )])
                };
                object(vec![(
                    "AND".into(),
                    Value::Array(vec![present(field), test]),
                )])
            }
            ResourceFilter::Compare {
                field,
                operator,
                value,
            } => object(vec![(
                "AND".into(),
                Value::Array(vec![
                    present(field),
                    object(vec![(
                        name(field),
                        object(vec![(
                            prisma_operator(*operator).into(),
                            js::number(*value).unwrap_or(Value::Null),
                        )]),
                    )]),
                ]),
            )]),
            ResourceFilter::Like {
                field,
                pattern,
                ignore_case,
            } => {
                let Some((kind, text)) = simple_glob(pattern) else {
                    return Err(unsupported("This wildcard", "Prisma"));
                };
                let mut test = vec![(kind.to_owned(), Value::String(text))];
                if *ignore_case {
                    test.push(("mode".into(), Value::String("insensitive".into())));
                }
                object(vec![(
                    "AND".into(),
                    Value::Array(vec![
                        present(field),
                        object(vec![(name(field), object(test))]),
                    ]),
                )])
            }
            ResourceFilter::Contains { field, value } => object(vec![(
                name(field),
                object(vec![("has".into(), value.to_value())]),
            )]),
            ResourceFilter::Date { .. } => return Err(unsupported("Date", "Prisma")),
            ResourceFilter::Ip { .. } => return Err(unsupported("IP address", "Prisma")),
        })
    }
    compile(filter, &name, &present)
}

// --- MongoDB -------------------------------------------------------------------------------------

fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if ".*+?^${}()|[]\\/".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A glob as an anchored regular expression source.
fn glob_regex(pattern: &str) -> String {
    let body: String = parse_glob(pattern)
        .into_iter()
        .map(|token| match token {
            GlobToken::Star => "[\\s\\S]*".to_owned(),
            GlobToken::Any => "[\\s\\S]".to_owned(),
            GlobToken::Char(c) => regex_escape(&c.to_string()),
        })
        .collect();
    format!("^{body}$")
}

/// A BSON regular expression in MongoDB Extended JSON v2 (the TypeScript compiler puts a `RegExp` object there).
pub fn mongo_regex(pattern: &str, options: &str) -> Value {
    object(vec![(
        "$regularExpression".into(),
        object(vec![
            ("pattern".into(), Value::String(pattern.to_owned())),
            ("options".into(), Value::String(options.to_owned())),
        ]),
    )])
}

/// The filter as a MongoDB query document (`filterToMongo`). Dates and IP addresses refuse with
/// UNSUPPORTED_FILTER. Case-insensitive `equals` values are BSON regular expressions written as Extended JSON
/// (`{"$regularExpression": {"pattern", "options"}}`), where the TypeScript compiler uses `RegExp` objects.
pub fn filter_to_mongo(filter: &ResourceFilter, field: FieldMapping<'_>) -> IamResult<Value> {
    let name = |plan_field: &str| {
        field
            .map(|mapping| mapping(plan_field))
            .unwrap_or_else(|| plan_field.to_owned())
    };
    fn compile(item: &ResourceFilter, name: &dyn Fn(&str) -> String) -> IamResult<Value> {
        let list = |filters: &[ResourceFilter]| -> IamResult<Value> {
            Ok(Value::Array(
                filters
                    .iter()
                    .map(|filter| compile(filter, name))
                    .collect::<IamResult<_>>()?,
            ))
        };
        Ok(match item {
            ResourceFilter::True => object(vec![]),
            ResourceFilter::False => object(vec![(
                name("id"),
                object(vec![("$in".into(), Value::Array(vec![]))]),
            )]),
            ResourceFilter::And(filters) => object(vec![("$and".into(), list(filters)?)]),
            ResourceFilter::Or(filters) => object(vec![("$or".into(), list(filters)?)]),
            ResourceFilter::Not(inner) => object(vec![(
                "$nor".into(),
                Value::Array(vec![compile(inner, name)?]),
            )]),
            ResourceFilter::Exists { field } => object(vec![(
                name(field),
                object(vec![
                    ("$exists".into(), Value::Bool(true)),
                    ("$ne".into(), Value::Null),
                ]),
            )]),
            ResourceFilter::Type { field, kind } => {
                let kind = match kind {
                    FilterType::Ip => return Err(unsupported("IP address", "MongoDB")),
                    FilterType::String => "string",
                    FilterType::Number => "number",
                    FilterType::Boolean => "bool",
                };
                object(vec![(
                    name(field),
                    object(vec![("$type".into(), Value::String(kind.into()))]),
                )])
            }
            ResourceFilter::Equals {
                field,
                values,
                ignore_case,
            } => {
                let values: Vec<Value> = values
                    .iter()
                    .map(|value| match value {
                        FilterValue::String(text) if *ignore_case => {
                            mongo_regex(&format!("^{}$", regex_escape(text)), "iu")
                        }
                        other => other.to_value(),
                    })
                    .collect();
                object(vec![(
                    name(field),
                    object(vec![("$in".into(), Value::Array(values))]),
                )])
            }
            ResourceFilter::Compare {
                field,
                operator,
                value,
            } => object(vec![(
                name(field),
                object(vec![(
                    format!("${}", prisma_operator(*operator)),
                    js::number(*value).unwrap_or(Value::Null),
                )]),
            )]),
            ResourceFilter::Like {
                field,
                pattern,
                ignore_case,
            } => {
                let source = if *ignore_case {
                    glob_regex(&js::to_lower(pattern))
                } else {
                    glob_regex(pattern)
                };
                object(vec![(
                    name(field),
                    object(vec![
                        ("$regex".into(), Value::String(source)),
                        (
                            "$options".into(),
                            Value::String(if *ignore_case { "iu" } else { "u" }.into()),
                        ),
                    ]),
                )])
            }
            ResourceFilter::Contains { field, value } => object(vec![(
                name(field),
                object(vec![(
                    "$elemMatch".into(),
                    object(vec![("$eq".into(), value.to_value())]),
                )]),
            )]),
            ResourceFilter::Date { .. } => return Err(unsupported("Date", "MongoDB")),
            ResourceFilter::Ip { .. } => return Err(unsupported("IP address", "MongoDB")),
        })
    }
    compile(filter, &name)
}

// --- description ---------------------------------------------------------------------------------

/// A readable rendering of a filter, for logs, UIs and tests (`describeFilter`).
pub fn describe_filter(filter: &ResourceFilter) -> String {
    let value = |item: &FilterValue| js::stringify(&item.to_value());
    let any_case = |ignore_case: bool| if ignore_case { " (any case)" } else { "" };
    match filter {
        ResourceFilter::True => "true".into(),
        ResourceFilter::False => "false".into(),
        ResourceFilter::And(filters) => filters
            .iter()
            .map(|item| {
                if matches!(item, ResourceFilter::Or(_)) {
                    format!("({})", describe_filter(item))
                } else {
                    describe_filter(item)
                }
            })
            .collect::<Vec<_>>()
            .join(" and "),
        ResourceFilter::Or(filters) => filters
            .iter()
            .map(|item| {
                if matches!(item, ResourceFilter::And(_)) {
                    format!("({})", describe_filter(item))
                } else {
                    describe_filter(item)
                }
            })
            .collect::<Vec<_>>()
            .join(" or "),
        ResourceFilter::Not(inner) => format!("not ({})", describe_filter(inner)),
        ResourceFilter::Exists { field } => format!("{field} exists"),
        ResourceFilter::Type { field, kind } => format!("{field} is {}", kind.as_str()),
        ResourceFilter::Equals {
            field,
            values,
            ignore_case,
        } => {
            if values.len() == 1 {
                format!("{field} = {}{}", value(&values[0]), any_case(*ignore_case))
            } else {
                format!(
                    "{field} in [{}]{}",
                    values.iter().map(value).collect::<Vec<_>>().join(", "),
                    any_case(*ignore_case)
                )
            }
        }
        ResourceFilter::Compare {
            field,
            operator,
            value,
        } => {
            format!(
                "{field} {} {}",
                comparison_symbol(*operator),
                js::number_to_string(*value)
            )
        }
        ResourceFilter::Like {
            field,
            pattern,
            ignore_case,
        } => {
            format!(
                "{field} like {}{}",
                js::quote(pattern),
                any_case(*ignore_case)
            )
        }
        ResourceFilter::Date {
            field,
            operator,
            value,
        } => format!("{field} {} {value}", operator.as_str()),
        ResourceFilter::Ip { field, network } => format!("{field} in {network}"),
        ResourceFilter::Contains { field, value: item } => {
            format!("{field} contains {}", value(item))
        }
    }
}
