//! The parts of JavaScript's `Date` the message templates use (Rust-only module): `new Date(string)` /
//! `Date.parse`, `new Date(number)`, `getTime()` and `toUTCString()`.
//!
//! Parsing accepts the ECMAScript date-time string format (`2026-10-01`, `2026-10-01T09:30:00.000Z`, with an offset,
//! or an expanded `+002026` year) and the RFC 7231 / RFC 2822 forms `toUTCString()` writes
//! (`Thu, 01 Oct 2026 00:00:00 GMT`). A date-time without an offset is read as UTC, which is what V8 does when the
//! process runs in UTC; other strings V8's legacy parser would accept read as an invalid date.

use better_iam_core::js;

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The largest time value a `Date` holds (±8.64e15 ms).
const MAX_TIME: f64 = 8.64e15;

/// `TimeClip`: NaN outside the representable range, otherwise the integer part.
pub fn time_clip(ms: f64) -> f64 {
    if !ms.is_finite() || ms.abs() > MAX_TIME {
        return f64::NAN;
    }
    ms.trunc() + 0.0
}

fn make_time(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    milli: f64,
) -> f64 {
    let days = js::days_from_civil(year, month, day);
    days as f64 * 86_400_000.0
        + hour as f64 * 3_600_000.0
        + minute as f64 * 60_000.0
        + second as f64 * 1000.0
        + milli
}

fn digits(text: &[u8], start: usize, count: usize) -> Option<i64> {
    let slice = text.get(start..start + count)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(slice).ok()?.parse().ok()
}

/// The ECMAScript date-time string format.
fn parse_iso(text: &str) -> Option<f64> {
    let b = text.as_bytes();
    let mut i;
    let year;
    match b.first()? {
        b'+' | b'-' => {
            let value = digits(b, 1, 6)?;
            if b[0] == b'-' && value == 0 {
                return None;
            }
            year = if b[0] == b'-' { -value } else { value };
            i = 7;
        }
        _ => {
            year = digits(b, 0, 4)?;
            i = 4;
        }
    }
    let mut month = 1;
    let mut day = 1;
    if b.get(i) == Some(&b'-') {
        month = digits(b, i + 1, 2)?;
        i += 3;
        if b.get(i) == Some(&b'-') {
            day = digits(b, i + 1, 2)?;
            i += 3;
        }
    }
    if !(1..=12).contains(&month) || day < 1 || day > js::days_in_month(year, month) {
        return None;
    }
    let (mut hour, mut minute, mut second, mut milli) = (0, 0, 0, 0.0);
    let mut offset_minutes = 0i64;
    if i < b.len() {
        if b[i] != b'T' && b[i] != b't' {
            return None;
        }
        hour = digits(b, i + 1, 2)?;
        if b.get(i + 3) != Some(&b':') {
            return None;
        }
        minute = digits(b, i + 4, 2)?;
        i += 6;
        if b.get(i) == Some(&b':') {
            second = digits(b, i + 1, 2)?;
            i += 3;
            if b.get(i) == Some(&b'.') {
                let start = i + 1;
                let mut end = start;
                while end < b.len() && b[end].is_ascii_digit() {
                    end += 1;
                }
                if end == start {
                    return None;
                }
                let fraction = std::str::from_utf8(&b[start..end]).ok()?;
                let first_three: String = fraction.chars().chain("000".chars()).take(3).collect();
                milli = first_three.parse::<f64>().ok()?;
                i = end;
            }
        }
        match b.get(i) {
            None => {}
            Some(b'Z' | b'z') => {
                i += 1;
            }
            Some(sign @ (b'+' | b'-')) => {
                let hours = digits(b, i + 1, 2)?;
                if b.get(i + 3) != Some(&b':') {
                    return None;
                }
                let minutes = digits(b, i + 4, 2)?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                offset_minutes = (hours * 60 + minutes) * if *sign == b'+' { 1 } else { -1 };
                i += 6;
            }
            _ => return None,
        }
        if i != b.len() {
            return None;
        }
        let midnight_end = hour == 24 && minute == 0 && second == 0 && milli == 0.0;
        if (hour > 23 && !midnight_end) || minute > 59 || second > 59 {
            return None;
        }
    }
    Some(
        make_time(year, month, day, hour, minute, second, milli) - offset_minutes as f64 * 60_000.0,
    )
}

/// `Thu, 01 Oct 2026 00:00:00 GMT` and the RFC 2822 variants (`+0000` offsets, an optional weekday).
fn parse_rfc(text: &str) -> Option<f64> {
    let mut tokens: Vec<&str> = text.split([' ', ',']).filter(|t| !t.is_empty()).collect();
    if tokens.first().is_some_and(|first| {
        DAYS.iter().any(|day| first.eq_ignore_ascii_case(day))
            || first.len() > 3 && DAYS.iter().any(|day| first[..3].eq_ignore_ascii_case(day))
    }) {
        tokens.remove(0);
    }
    if tokens.len() < 4 {
        return None;
    }
    let day: i64 = tokens[0].parse().ok()?;
    let month = MONTHS
        .iter()
        .position(|name| tokens[1].len() >= 3 && tokens[1][..3].eq_ignore_ascii_case(name))?
        as i64
        + 1;
    let year: i64 = tokens[2].parse().ok()?;
    let time: Vec<&str> = tokens[3].split(':').collect();
    if time.len() < 2 || time.len() > 3 {
        return None;
    }
    let hour: i64 = time[0].parse().ok()?;
    let minute: i64 = time[1].parse().ok()?;
    let second: i64 = time.get(2).map_or(Some(0), |s| s.parse().ok())?;
    if day < 1 || day > js::days_in_month(year, month) || hour > 24 || minute > 59 || second > 59 {
        return None;
    }
    let offset = match tokens.get(4) {
        None => 0,
        Some(zone)
            if ["GMT", "UTC", "UT", "Z"]
                .iter()
                .any(|name| zone.eq_ignore_ascii_case(name)) =>
        {
            0
        }
        Some(zone) if (zone.starts_with('+') || zone.starts_with('-')) && zone.len() == 5 => {
            let hours: i64 = zone[1..3].parse().ok()?;
            let minutes: i64 = zone[3..5].parse().ok()?;
            (hours * 60 + minutes) * if zone.starts_with('+') { 1 } else { -1 }
        }
        Some(_) => return None,
    };
    if tokens.len() > 5 {
        return None;
    }
    Some(make_time(year, month, day, hour, minute, second, 0.0) - offset as f64 * 60_000.0)
}

/// `Date.parse(text)` (the time value of `new Date(text)`); NaN for an invalid date.
pub fn parse(text: &str) -> f64 {
    let trimmed = js::trim(text);
    parse_iso(trimmed)
        .or_else(|| parse_rfc(trimmed))
        .map_or(f64::NAN, time_clip)
}

/// `new Date(ms).toUTCString()`; "Invalid Date" for NaN.
pub fn to_utc_string(ms: f64) -> String {
    let ms = time_clip(ms);
    if ms.is_nan() {
        return "Invalid Date".to_owned();
    }
    let ms = ms as i64;
    let days = ms.div_euclid(86_400_000);
    let rest = ms.rem_euclid(86_400_000);
    let (year, month, day) = js::civil_from_days(days);
    let weekday = (days + 4).rem_euclid(7) as usize;
    let year_text = if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("{year:04}")
    };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year_text,
        rest / 3_600_000,
        (rest / 60_000) % 60,
        (rest / 1000) % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iso_and_utc_strings() {
        let at = parse("2026-10-01T00:00:00.000Z");
        assert_eq!(at, 1_790_812_800_000.0);
        assert_eq!(to_utc_string(at), "Thu, 01 Oct 2026 00:00:00 GMT");
        assert_eq!(parse("2026-10-01"), at);
        assert_eq!(parse("Thu, 01 Oct 2026 00:00:00 GMT"), at);
        assert_eq!(parse("2026-10-01T02:00:00+02:00"), at);
        assert!(parse("not a date").is_nan());
        assert!(parse("2026-13-01").is_nan());
        assert_eq!(to_utc_string(f64::NAN), "Invalid Date");
    }
}
