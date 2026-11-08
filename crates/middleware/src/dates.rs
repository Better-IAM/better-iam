//! `Date.parse` for the dates cookies carry: the IMF-fixdate of RFC 9110 (`Thu, 01 Jan 1970 00:00:00 GMT`), its
//! RFC 850 and asctime relatives, the dashed cookie form (`Thu, 01-Jan-1970 00:00:00 GMT`), numeric offsets
//! (`+0100`, `GMT+0100`), and ISO 8601 (`1970-01-01T00:00:00Z`). Dates without a zone are read as UTC.

use better_iam_core::js::days_from_civil;

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Milliseconds since the epoch, or None when the text is not a date (`NaN`).
pub(crate) fn parse_date(text: &str) -> Option<f64> {
    let text = better_iam_core::js::trim(text);
    if text.is_empty() {
        return None;
    }
    iso(text).or_else(|| legacy(text))
}

fn to_ms(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: f64,
    offset_minutes: i64,
) -> Option<f64> {
    if !(1..=12).contains(&month)
        || !(1..=better_iam_core::js::days_in_month(year, month)).contains(&day)
        || !(0..=24).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0.0..60.0).contains(&second)
        || (hour == 24 && (minute != 0 || second != 0.0))
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 - offset_minutes * 60;
    Some(seconds as f64 * 1000.0 + (second * 1000.0).round())
}

fn number(text: &str) -> Option<i64> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// `YYYY-MM-DD`, optionally followed by `THH:MM[:SS[.sss]]` and `Z` or `±HH:MM`.
fn iso(text: &str) -> Option<f64> {
    let (date, time) = match text.find(['T', 't']) {
        Some(index) => (&text[..index], Some(&text[index + 1..])),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let year_text = parts.next()?;
    if year_text.len() != 4 {
        return None;
    }
    let year = number(year_text)?;
    let month = parts.next().map_or(Some(1), number)?;
    let day = parts.next().map_or(Some(1), number)?;
    if parts.next().is_some() {
        return None;
    }
    let Some(time) = time else {
        return to_ms(year, month, day, 0, 0, 0.0, 0);
    };
    let (clock, offset) = if let Some(clock) = time.strip_suffix(['Z', 'z']) {
        (clock, 0)
    } else if let Some(index) = time.rfind(['+', '-']) {
        let (clock, zone) = time.split_at(index);
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let zone = &zone[1..];
        let (hours, minutes) = zone.split_once(':').unwrap_or((zone, "0"));
        (clock, sign * (number(hours)? * 60 + number(minutes)?))
    } else {
        (time, 0)
    };
    let mut fields = clock.split(':');
    let hour = number(fields.next()?)?;
    let minute = number(fields.next()?)?;
    let second = match fields.next() {
        Some(second) => second
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())?,
        None => 0.0,
    };
    if fields.next().is_some() {
        return None;
    }
    to_ms(year, month, day, hour, minute, second, offset)
}

/// The legacy forms `Date.parse` accepts: a month name, a day, a year, a time, and an optional zone, in any order.
fn legacy(text: &str) -> Option<f64> {
    let mut month = None;
    let mut numbers: Vec<&str> = Vec::new();
    let mut clock = None;
    let mut offset = 0;
    for token in text
        .split(|c: char| better_iam_core::js::is_js_whitespace(c) || c == ',')
        .filter(|token| !token.is_empty())
    {
        if token.contains(':') {
            clock = Some(token);
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if let Some(zone) = lower
            .strip_prefix("gmt")
            .or_else(|| lower.strip_prefix("utc"))
            .or_else(|| lower.strip_prefix("ut"))
            .or_else(|| (lower == "z").then_some(""))
        {
            if !zone.is_empty() {
                offset = zone_offset(zone)?;
            }
            continue;
        }
        if token.starts_with(['+', '-']) && token.len() > 1 && number(&token[1..]).is_some() {
            offset = zone_offset(token)?;
            continue;
        }
        for piece in token.split('-').filter(|piece| !piece.is_empty()) {
            if piece.bytes().all(|byte| byte.is_ascii_digit()) {
                numbers.push(piece);
            } else if piece.len() >= 3 {
                let prefix = piece[..3].to_ascii_lowercase();
                if let Some(index) = MONTHS.iter().position(|name| *name == prefix) {
                    month = Some(index as i64 + 1);
                }
                // Weekday names and other words are ignored, as `Date.parse` ignores them.
            } else {
                return None;
            }
        }
    }
    let month = month?;
    let (mut day, mut year) = (None, None);
    for text in numbers {
        let value = number(text)?;
        if day.is_none() && text.len() <= 2 && (1..=31).contains(&value) {
            day = Some(value);
        } else if year.is_none() {
            year = Some(if text.len() <= 2 {
                if value < 50 {
                    2000 + value
                } else {
                    1900 + value
                }
            } else {
                value
            });
        } else {
            return None;
        }
    }
    let (hour, minute, second) = match clock {
        Some(clock) => {
            let mut fields = clock.split(':');
            let hour = number(fields.next()?)?;
            let minute = number(fields.next()?)?;
            let second = fields.next().map_or(Some(0), number)?;
            (hour, minute, second as f64)
        }
        None => (0, 0, 0.0),
    };
    to_ms(year?, month, day.unwrap_or(1), hour, minute, second, offset)
}

/// `+hhmm`, `-hh:mm` or `+hh` as minutes east of UTC.
fn zone_offset(zone: &str) -> Option<i64> {
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits: String = zone[1..].chars().filter(|c| *c != ':').collect();
    let value = number(&digits)?;
    let (hours, minutes) = if digits.len() <= 2 {
        (value, 0)
    } else {
        (value / 100, value % 100)
    };
    Some(sign * (hours * 60 + minutes))
}

#[cfg(test)]
mod tests {
    use super::parse_date;

    #[test]
    fn parses_cookie_dates() {
        assert_eq!(parse_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0.0));
        assert_eq!(parse_date("Thu, 01-Jan-1970 00:00:01 GMT"), Some(1000.0));
        assert_eq!(parse_date("Thursday, 01-Jan-70 00:00:00 GMT"), Some(0.0));
        assert_eq!(parse_date("Thu Jan  1 00:00:00 1970"), Some(0.0));
        assert_eq!(
            parse_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(1_445_412_480_000.0)
        );
        assert_eq!(parse_date("Thu, 01 Jan 1970 01:00:00 +0100"), Some(0.0));
        assert_eq!(parse_date("1970-01-01T00:00:00Z"), Some(0.0));
        assert_eq!(parse_date("1970-01-02"), Some(86_400_000.0));
        assert_eq!(parse_date("1970-01-01T01:00:00.500+01:00"), Some(500.0));
        assert_eq!(parse_date("not a date"), None);
        assert_eq!(parse_date(""), None);
        assert_eq!(parse_date("Thu, 32 Jan 1970 00:00:00 GMT"), None);
    }
}
