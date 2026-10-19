//! Security classification (`classification.ts`): the pure lattice behind clearances and mandatory access control.
//! A tenant's scheme orders classification levels by rank and lists its compartments and the dissemination controls
//! it uses. A label marks one resource. A party may read a labeled resource only when its adjudicated clearance
//! dominates the label (no read up). Labels are untrusted JSON here, as in the TypeScript functions, which accept
//! `unknown` and fail closed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::js;
use crate::{IamError, IamResult};

/// One level of a scheme (`ClassificationLevel`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationLevel {
    pub id: String,
    pub name: String,
    pub rank: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abbreviation: Option<String>,
}

/// A compartment (`Compartment`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compartment {
    pub id: String,
    pub name: String,
}

/// A validated scheme (`ClassificationSchemeDefinition`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationSchemeDefinition {
    pub levels: Vec<ClassificationLevel>,
    pub compartments: Vec<Compartment>,
    pub owner_countries: Vec<String>,
    pub caveats: Vec<String>,
}

/// The classification of one resource, normalized (`ClassificationLabel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationLabel {
    pub level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compartments: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noforn: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releasable_to: Option<Vec<String>>,
}

impl ClassificationLabel {
    /// The label as JSON.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// One person or agent taking part in a decision (`ClearanceParty`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClearanceParty {
    pub identity_id: String,
    /// The rank of the cleared level; -1 = no clearance.
    pub rank: f64,
    pub compartments: BTreeSet<String>,
    pub citizenship: BTreeSet<String>,
}

/// Which dimension a party failed (`DominanceFailure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DominanceFailure {
    Level,
    Compartment,
    Noforn,
    Releasability,
    InvalidLabel,
}

impl DominanceFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            DominanceFailure::Level => "level",
            DominanceFailure::Compartment => "compartment",
            DominanceFailure::Noforn => "noforn",
            DominanceFailure::Releasability => "releasability",
            DominanceFailure::InvalidLabel => "invalid-label",
        }
    }
}

/// `classificationIdPattern`: an ASCII letter or digit, then letters, digits, `.`, `_`, `:` or `-` (64 at most).
pub fn classification_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn country(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// The bounds [`validate_scheme`] and [`validate_label`] enforce (`classificationLimits`).
pub mod limits {
    pub const MIN_LEVELS: usize = 2;
    pub const MAX_LEVELS: usize = 20;
    pub const MAX_RANK: f64 = 999.0;
    pub const MAX_COMPARTMENTS: usize = 200;
    pub const MAX_OWNER_COUNTRIES: usize = 64;
    pub const MAX_RELEASABLE_TO: usize = 300;
    pub const MAX_LEVEL_NAME_LENGTH: usize = 64;
    pub const MAX_COMPARTMENT_NAME_LENGTH: usize = 128;
    pub const MAX_ABBREVIATION_LENGTH: usize = 16;
}

const CAVEATS: [&str; 2] = ["NOFORN", "RELTO"];
const SCHEME_KEYS: [&str; 4] = ["levels", "compartments", "ownerCountries", "caveats"];
const LEVEL_KEYS: [&str; 4] = ["id", "name", "rank", "abbreviation"];
const COMPARTMENT_KEYS: [&str; 2] = ["id", "name"];
const LABEL_KEYS: [&str; 4] = ["level", "compartments", "noforn", "releasableTo"];
/// Names `value in Object.prototype` finds that the id pattern admits.
const PROTOTYPE_NAMES: [&str; 7] = [
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "toLocaleString",
];

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn only_keys(value: &Map<String, Value>, allowed: &[&str]) -> bool {
    value.keys().all(|key| allowed.contains(&key.as_str()))
}

/// An id that cannot be mistaken for an inherited property.
fn identifier(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| classification_id(text) && !PROTOTYPE_NAMES.contains(text))
}

/// Display text: trimmed and non-empty, without control, separator, bidirectional or zero-width-no-break characters.
fn text(value: Option<&Value>, max: usize) -> Option<&str> {
    let text = value?.as_str()?;
    let length = js::utf16_len(text);
    if length == 0 || length > max || js::trim(text) != text {
        return None;
    }
    let forbidden = |code: u32| {
        code < 0x20
            || (0x7f..=0x9f).contains(&code)
            || code == 0x061c
            || code == 0x200e
            || code == 0x200f
            || (0x2028..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
            || code == 0xfeff
    };
    (!text.chars().any(|c| forbidden(c as u32))).then_some(text)
}

/// True when every string is distinct, ignoring case.
fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let values: Vec<String> = values.map(js::to_lower).collect();
    let unique: std::collections::HashSet<&String> = values.iter().collect();
    unique.len() == values.len()
}

/// Validates a scheme definition and returns a fresh copy (`validateScheme`). Absent `compartments`,
/// `ownerCountries` and `caveats` read as empty. Messages name positions, never submitted values.
pub fn validate_scheme(input: &Value) -> IamResult<ClassificationSchemeDefinition> {
    let Value::Object(input) = input else {
        return Err(invalid("The classification scheme must be an object"));
    };
    if !only_keys(input, &SCHEME_KEYS) {
        return Err(invalid("Unknown classification scheme field"));
    }
    let empty = Value::Array(Vec::new());
    let levels = input.get("levels");
    let compartments = input.get("compartments").unwrap_or(&empty);
    let owner_countries = input.get("ownerCountries").unwrap_or(&empty);
    let caveats = input.get("caveats").unwrap_or(&empty);
    let levels = match levels {
        Some(Value::Array(levels))
            if (limits::MIN_LEVELS..=limits::MAX_LEVELS).contains(&levels.len()) =>
        {
            levels
        }
        _ => {
            return Err(invalid(format!(
                "A classification scheme needs {} to {} levels",
                limits::MIN_LEVELS,
                limits::MAX_LEVELS
            )));
        }
    };
    let mut out_levels: Vec<ClassificationLevel> = Vec::new();
    for (index, level) in levels.iter().enumerate() {
        let Value::Object(level) = level else {
            return Err(invalid(format!("levels[{index}] must be an object")));
        };
        if !only_keys(level, &LEVEL_KEYS) {
            return Err(invalid(format!("levels[{index}] has an unknown field")));
        }
        let Some(id) = identifier(level.get("id")) else {
            return Err(invalid(format!(
                "levels[{index}].id is not a valid identifier"
            )));
        };
        let Some(name) = text(level.get("name"), limits::MAX_LEVEL_NAME_LENGTH) else {
            return Err(invalid(format!(
                "levels[{index}].name must be 1 to {} printable characters",
                limits::MAX_LEVEL_NAME_LENGTH
            )));
        };
        let rank = level.get("rank").and_then(js::as_number);
        let Some(rank) =
            rank.filter(|rank| js::is_safe_integer(*rank) && *rank <= limits::MAX_RANK)
        else {
            return Err(invalid(format!(
                "levels[{index}].rank must be an integer from 0 to {}",
                limits::MAX_RANK
            )));
        };
        let increasing = match out_levels.last() {
            Some(previous) => rank > previous.rank,
            None => rank == 0.0,
        };
        if !increasing {
            return Err(invalid(
                "Level ranks must start at 0 and strictly increase in the order the levels are listed",
            ));
        }
        let abbreviation = match level.get("abbreviation") {
            None => None,
            Some(value) => match text(Some(value), limits::MAX_ABBREVIATION_LENGTH) {
                Some(abbreviation) => Some(abbreviation.to_owned()),
                None => {
                    return Err(invalid(format!(
                        "levels[{index}].abbreviation must be 1 to {} printable characters",
                        limits::MAX_ABBREVIATION_LENGTH
                    )));
                }
            },
        };
        out_levels.push(ClassificationLevel {
            id: id.to_owned(),
            name: name.to_owned(),
            rank,
            abbreviation,
        });
    }
    if !distinct(out_levels.iter().map(|level| level.id.as_str())) {
        return Err(invalid("Level ids must be unique, ignoring case"));
    }
    if !distinct(out_levels.iter().map(|level| level.name.as_str())) {
        return Err(invalid("Level names must be unique, ignoring case"));
    }
    if !distinct(
        out_levels
            .iter()
            .filter_map(|level| level.abbreviation.as_deref()),
    ) {
        return Err(invalid("Level abbreviations must be unique, ignoring case"));
    }

    let compartments = match compartments {
        Value::Array(items) if items.len() <= limits::MAX_COMPARTMENTS => items,
        _ => {
            return Err(invalid(format!(
                "A classification scheme has at most {} compartments",
                limits::MAX_COMPARTMENTS
            )));
        }
    };
    let mut out_compartments = Vec::new();
    for (index, compartment) in compartments.iter().enumerate() {
        let Value::Object(compartment) = compartment else {
            return Err(invalid(format!("compartments[{index}] must be an object")));
        };
        if !only_keys(compartment, &COMPARTMENT_KEYS) {
            return Err(invalid(format!(
                "compartments[{index}] has an unknown field"
            )));
        }
        let Some(id) = identifier(compartment.get("id")) else {
            return Err(invalid(format!(
                "compartments[{index}].id is not a valid identifier"
            )));
        };
        let Some(name) = text(compartment.get("name"), limits::MAX_COMPARTMENT_NAME_LENGTH) else {
            return Err(invalid(format!(
                "compartments[{index}].name must be 1 to {} printable characters",
                limits::MAX_COMPARTMENT_NAME_LENGTH
            )));
        };
        out_compartments.push(Compartment {
            id: id.to_owned(),
            name: name.to_owned(),
        });
    }
    if !distinct(
        out_compartments
            .iter()
            .map(|compartment| compartment.id.as_str()),
    ) {
        return Err(invalid("Compartment ids must be unique, ignoring case"));
    }
    if !distinct(
        out_compartments
            .iter()
            .map(|compartment| compartment.name.as_str()),
    ) {
        return Err(invalid("Compartment names must be unique, ignoring case"));
    }

    let owner_countries = match owner_countries {
        Value::Array(items) if items.len() <= limits::MAX_OWNER_COUNTRIES => items,
        _ => {
            return Err(invalid(format!(
                "ownerCountries must list at most {} countries",
                limits::MAX_OWNER_COUNTRIES
            )));
        }
    };
    let mut out_owners: Vec<String> = Vec::new();
    for owner in owner_countries {
        match owner.as_str() {
            Some(code) if country(code) => out_owners.push(code.to_owned()),
            _ => {
                return Err(invalid(
                    "ownerCountries must be ISO 3166-1 alpha-3 codes in upper case",
                ));
            }
        }
    }
    if out_owners
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != out_owners.len()
    {
        return Err(invalid("ownerCountries must not repeat a country"));
    }

    let Value::Array(caveats) = caveats else {
        return Err(invalid("caveats must be a list"));
    };
    let mut out_caveats: Vec<String> = Vec::new();
    for caveat in caveats {
        match caveat.as_str() {
            Some(name) if CAVEATS.contains(&name) => out_caveats.push(name.to_owned()),
            _ => return Err(invalid("caveats may be NOFORN and RELTO only")),
        }
    }
    if out_caveats
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != out_caveats.len()
    {
        return Err(invalid("caveats must not repeat a caveat"));
    }
    if out_caveats.iter().any(|caveat| caveat == "NOFORN") && out_owners.is_empty() {
        return Err(invalid(
            "The NOFORN caveat needs at least one owner country",
        ));
    }
    Ok(ClassificationSchemeDefinition {
        levels: out_levels,
        compartments: out_compartments,
        owner_countries: out_owners,
        caveats: out_caveats,
    })
}

fn sorted_utf16(mut values: Vec<String>) -> Vec<String> {
    values.sort_by(|left, right| js::cmp_utf16(left, right));
    values
}

/// The checked, normalized label, or why it is invalid for the scheme (`checkLabel`).
fn check_label(
    label: &Value,
    scheme: &ClassificationSchemeDefinition,
) -> Result<ClassificationLabel, String> {
    let Value::Object(label) = label else {
        return Err("A classification label must be an object".into());
    };
    if !only_keys(label, &LABEL_KEYS) {
        return Err("Unknown classification label field".into());
    }
    let level = match label.get("level").and_then(Value::as_str) {
        Some(level) if scheme.levels.iter().any(|known| known.id == level) => level,
        _ => return Err("The label names a level the scheme does not define".into()),
    };
    let mut out_compartments: Vec<String> = Vec::new();
    if let Some(compartments) = label.get("compartments") {
        let compartments = match compartments {
            Value::Array(items) if items.len() <= limits::MAX_COMPARTMENTS => items,
            _ => return Err("Label compartments must be a list of compartment ids".into()),
        };
        let mut seen: Vec<String> = Vec::new();
        for compartment in compartments {
            let Some(id) = compartment
                .as_str()
                .filter(|id| scheme.compartments.iter().any(|known| known.id == *id))
            else {
                return Err("The label names a compartment the scheme does not define".into());
            };
            if seen.iter().any(|existing| existing == id) {
                return Err("Label compartments must not repeat".into());
            }
            seen.push(id.to_owned());
        }
        out_compartments = sorted_utf16(seen);
    }
    let noforn = label.get("noforn");
    if noforn.is_some_and(|value| !value.is_boolean()) {
        return Err("Label noforn must be a boolean".into());
    }
    let noforn = noforn.and_then(Value::as_bool) == Some(true);
    if noforn && !scheme.caveats.iter().any(|caveat| caveat == "NOFORN") {
        return Err("The scheme does not use the NOFORN caveat".into());
    }
    let mut out_releasable = None;
    if let Some(releasable) = label.get("releasableTo") {
        if !scheme.caveats.iter().any(|caveat| caveat == "RELTO") {
            return Err("The scheme does not use the RELTO caveat".into());
        }
        let releasable = match releasable {
            Value::Array(items) if items.len() <= limits::MAX_RELEASABLE_TO => items,
            _ => {
                return Err(format!(
                    "Label releasableTo must list at most {} countries",
                    limits::MAX_RELEASABLE_TO
                ));
            }
        };
        let mut seen: Vec<String> = Vec::new();
        for code in releasable {
            let Some(code) = code.as_str().filter(|code| country(code)) else {
                return Err(
                    "Label releasableTo must hold ISO 3166-1 alpha-3 codes in upper case".into(),
                );
            };
            if seen.iter().any(|existing| existing == code) {
                return Err("Label releasableTo must not repeat a country".into());
            }
            seen.push(code.to_owned());
        }
        out_releasable = Some(sorted_utf16(seen));
    }
    Ok(ClassificationLabel {
        level: level.to_owned(),
        compartments: (!out_compartments.is_empty()).then_some(out_compartments),
        noforn: noforn.then_some(true),
        releasable_to: out_releasable,
    })
}

/// Validates a label against a scheme and returns it normalized (`validateLabel`): compartments and countries
/// sorted, an empty compartment list and `noforn: false` dropped, an empty `releasableTo` kept.
pub fn validate_label(
    label: &Value,
    scheme: &ClassificationSchemeDefinition,
) -> IamResult<ClassificationLabel> {
    check_label(label, scheme).map_err(invalid)
}

/// True when `label` is a valid label of the scheme (`isValidClassificationLabel`).
pub fn is_valid_classification_label(
    label: &Value,
    scheme: &ClassificationSchemeDefinition,
) -> bool {
    check_label(label, scheme).is_ok()
}

/// The rank of the label's level in the scheme; None when the level is unknown (`labelRank`).
pub fn label_rank(label: &Value, scheme: &ClassificationSchemeDefinition) -> Option<f64> {
    let level = label.as_object()?.get("level")?.as_str()?;
    scheme
        .levels
        .iter()
        .find(|known| known.id == level)
        .map(|known| known.rank)
}

fn rank_of(label: &ClassificationLabel, scheme: &ClassificationSchemeDefinition) -> Option<f64> {
    scheme
        .levels
        .iter()
        .find(|known| known.id == label.level)
        .map(|known| known.rank)
}

/// The least restrictive label at least as restrictive as both (`joinLabels`). Absent (`None` or JSON `null`)
/// inputs are ignored; both absent gives None. An input that is not a valid label of the scheme makes the result that
/// input unchanged, so it stays invalid and [`dominates`] refuses every party.
pub fn join_labels(
    a: Option<&Value>,
    b: Option<&Value>,
    scheme: &ClassificationSchemeDefinition,
) -> Option<Value> {
    let a = a.filter(|value| !value.is_null());
    let b = b.filter(|value| !value.is_null());
    let left = match a {
        None => None,
        Some(value) => match check_label(value, scheme) {
            Ok(label) => Some(label),
            Err(_) => return Some(value.clone()),
        },
    };
    let right = match b {
        None => None,
        Some(value) => match check_label(value, scheme) {
            Ok(label) => Some(label),
            Err(_) => return Some(value.clone()),
        },
    };
    let (left, right) = match (left, right) {
        (Some(left), Some(right)) => (left, right),
        (left, right) => return left.or(right).map(|label| label.to_value()),
    };
    let level = if rank_of(&left, scheme).unwrap_or(0.0) >= rank_of(&right, scheme).unwrap_or(0.0) {
        left.level.clone()
    } else {
        right.level.clone()
    };
    let mut compartments: Vec<String> = Vec::new();
    for compartment in left
        .compartments
        .iter()
        .flatten()
        .chain(right.compartments.iter().flatten())
    {
        if !compartments.contains(compartment) {
            compartments.push(compartment.clone());
        }
    }
    let compartments = sorted_utf16(compartments);
    let releasable_to = match (&left.releasable_to, &right.releasable_to) {
        (Some(left), Some(right)) => Some(
            left.iter()
                .filter(|code| right.contains(code))
                .cloned()
                .collect(),
        ),
        (left, right) => left.clone().or_else(|| right.clone()),
    };
    let joined = ClassificationLabel {
        level,
        compartments: (!compartments.is_empty()).then_some(compartments),
        noforn: (left.noforn == Some(true) || right.noforn == Some(true)).then_some(true),
        releasable_to,
    };
    Some(joined.to_value())
}

/// The countries whose citizens may read a valid label, or None when releasability is unrestricted.
fn releasable_set(
    label: &ClassificationLabel,
    scheme: &ClassificationSchemeDefinition,
) -> Option<BTreeSet<String>> {
    if label.noforn == Some(true) {
        return Some(scheme.owner_countries.iter().cloned().collect());
    }
    label.releasable_to.as_ref().map(|codes| {
        codes
            .iter()
            .chain(&scheme.owner_countries)
            .cloned()
            .collect()
    })
}

/// Whether a party may read a resource carrying `label` (`dominates`): None when it may, or the first dimension it
/// fails.
pub fn dominates(
    party: &ClearanceParty,
    label: &Value,
    scheme: &ClassificationSchemeDefinition,
) -> Option<DominanceFailure> {
    let Ok(checked) = check_label(label, scheme) else {
        return Some(DominanceFailure::InvalidLabel);
    };
    let required = rank_of(&checked, scheme);
    match required {
        Some(required) if js::is_safe_integer(party.rank) && party.rank >= required => {}
        _ => return Some(DominanceFailure::Level),
    }
    if checked
        .compartments
        .iter()
        .flatten()
        .any(|compartment| !party.compartments.contains(compartment))
    {
        return Some(DominanceFailure::Compartment);
    }
    if checked.noforn == Some(true)
        && !scheme
            .owner_countries
            .iter()
            .any(|code| party.citizenship.contains(code))
    {
        return Some(DominanceFailure::Noforn);
    }
    if let Some(releasable) = &checked.releasable_to
        && !releasable
            .iter()
            .chain(&scheme.owner_countries)
            .any(|code| party.citizenship.contains(code))
    {
        return Some(DominanceFailure::Releasability);
    }
    None
}

/// True when replacing `lower` with `upper` never declassifies (`labelCovers`).
pub fn label_covers(upper: &Value, lower: &Value, scheme: &ClassificationSchemeDefinition) -> bool {
    let (Ok(high), Ok(low)) = (check_label(upper, scheme), check_label(lower, scheme)) else {
        return false;
    };
    if rank_of(&high, scheme).unwrap_or(-1.0) < rank_of(&low, scheme).unwrap_or(f64::INFINITY) {
        return false;
    }
    if low.compartments.iter().flatten().any(|compartment| {
        !high
            .compartments
            .iter()
            .flatten()
            .any(|item| item == compartment)
    }) {
        return false;
    }
    if low.noforn == Some(true) && high.noforn != Some(true) {
        return false;
    }
    let high_reach = releasable_set(&high, scheme);
    let Some(low_reach) = releasable_set(&low, scheme) else {
        return true;
    };
    high_reach.is_some_and(|high_reach| high_reach.iter().all(|code| low_reach.contains(code)))
}

/// `ClassificationTemplateName`.
pub const CLASSIFICATION_TEMPLATE_NAMES: [&str; 4] = ["us", "uk", "nato", "corporate"];

fn level(id: &str, name: &str, rank: f64, abbreviation: Option<&str>) -> ClassificationLevel {
    ClassificationLevel {
        id: id.into(),
        name: name.into(),
        rank,
        abbreviation: abbreviation.map(str::to_owned),
    }
}

/// The built-in starting points for a tenant's scheme (`classificationTemplates`); None for an unknown name.
pub fn classification_template(name: &str) -> Option<ClassificationSchemeDefinition> {
    let strings = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    Some(match name {
        "us" => ClassificationSchemeDefinition {
            levels: vec![
                level("U", "UNCLASSIFIED", 0.0, Some("U")),
                level("C", "CONFIDENTIAL", 1.0, Some("C")),
                level("S", "SECRET", 2.0, Some("S")),
                level("TS", "TOP SECRET", 3.0, Some("TS")),
            ],
            compartments: vec![],
            owner_countries: strings(&["USA"]),
            caveats: strings(&["NOFORN", "RELTO"]),
        },
        "uk" => ClassificationSchemeDefinition {
            levels: vec![
                level("OFFICIAL", "OFFICIAL", 0.0, Some("O")),
                level("SECRET", "SECRET", 1.0, Some("S")),
                level("TOP-SECRET", "TOP SECRET", 2.0, Some("TS")),
            ],
            compartments: vec![],
            owner_countries: strings(&["GBR"]),
            caveats: strings(&["NOFORN", "RELTO"]),
        },
        "nato" => ClassificationSchemeDefinition {
            levels: vec![
                level("NU", "NATO UNCLASSIFIED", 0.0, Some("NU")),
                level("NR", "NATO RESTRICTED", 1.0, Some("NR")),
                level("NC", "NATO CONFIDENTIAL", 2.0, Some("NC")),
                level("NS", "NATO SECRET", 3.0, Some("NS")),
                level("CTS", "COSMIC TOP SECRET", 4.0, Some("CTS")),
            ],
            compartments: vec![],
            owner_countries: vec![],
            caveats: strings(&["RELTO"]),
        },
        "corporate" => ClassificationSchemeDefinition {
            levels: vec![
                level("public", "Public", 0.0, None),
                level("internal", "Internal", 1.0, None),
                level("confidential", "Confidential", 2.0, None),
                level("restricted", "Restricted", 3.0, None),
            ],
            compartments: vec![],
            owner_countries: vec![],
            caveats: vec![],
        },
        _ => return None,
    })
}
