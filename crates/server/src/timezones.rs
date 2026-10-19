//! Time zones as `Intl.DateTimeFormat` resolves them (Rust-only module): IANA names case-insensitively, their
//! backward links, ICU's legacy identifiers (`PST`, `SystemV/EST5`), and UTC offsets (`±HH`, `±HHMM`, `±HH:MM`). The
//! accepted names are generated from Node (`tools/gen-timezones.mjs` → `timezones_gen.rs`); rules come from jiff's
//! bundled tzdb.

#[path = "timezones_gen.rs"]
mod generated;

use std::sync::{LazyLock, Mutex};

use indexmap::IndexMap;
use jiff::Timestamp;
use jiff::tz::{Offset, TimeZone};

use crate::js::ThrownError;

/// ICU's `SystemV/*` identifiers have no tzdb entry; these are the tzdb zones with the same rules (the two without
/// an exact tzdb equivalent, AST4ADT and YST9YDT, use the nearest US-rules zone).
const SYSTEM_V: [(&str, &str); 13] = [
    ("SystemV/AST4", "Etc/GMT+4"),
    ("SystemV/AST4ADT", "America/Halifax"),
    ("SystemV/CST6", "Etc/GMT+6"),
    ("SystemV/CST6CDT", "CST6CDT"),
    ("SystemV/EST5", "Etc/GMT+5"),
    ("SystemV/EST5EDT", "EST5EDT"),
    ("SystemV/HST10", "Etc/GMT+10"),
    ("SystemV/MST7", "Etc/GMT+7"),
    ("SystemV/MST7MDT", "MST7MDT"),
    ("SystemV/PST8", "Etc/GMT+8"),
    ("SystemV/PST8PDT", "PST8PDT"),
    ("SystemV/YST9", "Etc/GMT+9"),
    ("SystemV/YST9YDT", "America/Anchorage"),
];

fn table() -> &'static IndexMap<&'static str, &'static str> {
    static TABLE: LazyLock<IndexMap<&'static str, &'static str>> =
        LazyLock::new(|| generated::TIME_ZONE_NAMES.iter().copied().collect());
    &TABLE
}

/// The canonical IANA name `Intl` resolves an accepted name to (`resolvedOptions().timeZone`), or None when `Intl`
/// refuses the name. Offsets are not names (see [`load_time_zone`]).
pub fn canonical_time_zone(name: &str) -> Option<&'static str> {
    table().get(name.to_lowercase().as_str()).copied()
}

/// `^([+-])([01]\d|2[0-3])(?::?([0-5]\d))?$`: an offset zone in seconds east of UTC.
fn offset_zone(name: &str) -> Option<i32> {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || !matches!(bytes[0], b'+' | b'-') {
        return None;
    }
    let digit = |index: usize| {
        bytes
            .get(index)
            .filter(|b| b.is_ascii_digit())
            .map(|b| (b - b'0') as i32)
    };
    let hours = digit(1)? * 10 + digit(2)?;
    if hours > 23 {
        return None;
    }
    let rest = &bytes[3..];
    let minutes = match rest.len() {
        0 => 0,
        2 => digit(3)? * 10 + digit(4)?,
        3 if rest[0] == b':' => digit(4)? * 10 + digit(5)?,
        _ => return None,
    };
    if minutes > 59 {
        return None;
    }
    let seconds = hours * 3600 + minutes * 60;
    Some(if bytes[0] == b'-' { -seconds } else { seconds })
}

static CACHE: LazyLock<Mutex<IndexMap<String, TimeZone>>> =
    LazyLock::new(|| Mutex::new(IndexMap::new()));

/// Resolves a time zone as `Intl.DateTimeFormat` does; a `RangeError` for anything else.
pub fn load_time_zone(name: &str) -> Result<TimeZone, ThrownError> {
    let invalid = || ThrownError::new("RangeError", format!("Invalid time zone specified: {name}"));
    if let Some(zone) = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(name)
    {
        return Ok(zone.clone());
    }
    let zone = if let Some(seconds) = offset_zone(name) {
        TimeZone::fixed(Offset::from_seconds(seconds).map_err(|_| invalid())?)
    } else {
        let canonical = canonical_time_zone(name).ok_or_else(invalid)?;
        let canonical = SYSTEM_V
            .iter()
            .find(|(legacy, _)| *legacy == canonical)
            .map(|(_, zone)| *zone)
            .unwrap_or(canonical);
        TimeZone::get(canonical).map_err(|_| invalid())?
    };
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(name.to_owned(), zone.clone());
    Ok(zone)
}

/// Whether `new Intl.DateTimeFormat('en-US', { timeZone })` accepts the name.
pub fn is_valid_time_zone(name: &str) -> bool {
    load_time_zone(name).is_ok()
}

/// The local weekday (0 = Sunday) and minute of day of an instant (epoch milliseconds) in a time zone, as
/// `formatToParts` with `weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'` reports them.
pub fn local_time(at: f64, time_zone: &str) -> Result<(u8, u32), ThrownError> {
    let zone = load_time_zone(time_zone)?;
    if !at.is_finite() || at.abs() > 8.64e15 {
        return Err(ThrownError::new("RangeError", "Invalid time value"));
    }
    let timestamp = Timestamp::from_millisecond(at.trunc() as i64)
        .map_err(|_| ThrownError::new("RangeError", "Invalid time value"))?;
    let local = timestamp.to_zoned(zone);
    let day = local.weekday().to_sunday_zero_offset() as u8;
    let minutes = (local.hour() as u32 % 24) * 60 + local.minute() as u32;
    Ok((day, minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_offsets() {
        for name in [
            "UTC",
            "utc",
            "Europe/Berlin",
            "europe/berlin",
            "US/Pacific",
            "PST",
            "+05:30",
            "-0800",
            "+14",
        ] {
            assert!(is_valid_time_zone(name), "{name}");
        }
        for name in ["Mars/Base", "Z", "+24:00", "Etc/Unknown", ""] {
            assert!(!is_valid_time_zone(name), "{name}");
        }
        // 2024-01-01T00:00:00Z was a Monday.
        assert_eq!(local_time(1_704_067_200_000.0, "UTC").unwrap(), (1, 0));
        assert_eq!(
            local_time(1_704_067_200_000.0, "America/New_York").unwrap(),
            (0, 19 * 60)
        );
        assert_eq!(local_time(1_704_067_200_000.0, "+05:30").unwrap(), (1, 330));
        assert!(local_time(f64::NAN, "UTC").is_err());
    }

    #[test]
    fn every_accepted_name_has_rules() {
        for (name, _) in generated::TIME_ZONE_NAMES {
            assert!(load_time_zone(name).is_ok(), "{name}");
        }
    }
}
