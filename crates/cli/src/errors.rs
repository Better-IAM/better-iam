//! Command-line failures (`errors.ts`): an [`IamError`] with an optional hint, usage mistakes, and "did you mean"
//! suggestions.

use std::cmp::Ordering;
use std::fmt;

use better_iam_core::IamError;
use better_iam_server::metrics::locale_compare;

/// A command-line failure: an `IamError` (same `code` contract) that may carry a hint, printed on its own line by the
/// `better-iam` binary, telling the person what to run or set next (`CliError`).
#[derive(Debug, Clone)]
pub struct CliError(Box<CliFailure>);

/// The members of a [`CliError`] (boxed, so results stay small).
#[derive(Debug, Clone)]
pub struct CliFailure {
    pub error: IamError,
    /// One sentence saying what to do next, such as the command or flag that fixes the problem.
    pub hint: Option<String>,
    /// A command run by `vault-run` failed: the binary exits with its status, as the command itself would have.
    pub exit_status: Option<i32>,
    /// Whether the message says what went wrong without leaking details: IAM errors (local or remote) and system
    /// errors (`ENOENT`, `EEXIST`). Anything else (a failed network request, a driver failure) is reported generically
    /// unless `BETTER_IAM_DEBUG` is set.
    pub known: bool,
    /// The underlying failure of an unknown error, printed only with `BETTER_IAM_DEBUG`.
    pub debug: Option<String>,
}

impl std::ops::Deref for CliError {
    type Target = CliFailure;
    fn deref(&self) -> &CliFailure {
        &self.0
    }
}

impl std::ops::DerefMut for CliError {
    fn deref_mut(&mut self) -> &mut CliFailure {
        &mut self.0
    }
}

/// `Result<T, CliError>`.
pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    /// `new CliError(code, message, hint?)`.
    pub fn new(code: impl Into<String>, message: impl Into<String>, hint: Option<&str>) -> Self {
        Self(Box::new(CliFailure {
            error: IamError::new(code, message),
            hint: hint.map(str::to_owned),
            exit_status: None,
            known: true,
            debug: None,
        }))
    }

    /// A `CliError` with a hint.
    pub fn hinted(
        code: impl Into<String>,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self(Box::new(CliFailure {
            error: IamError::new(code, message),
            hint: Some(hint.into()),
            exit_status: None,
            known: true,
            debug: None,
        }))
    }

    /// A failure whose details are not shown unless `BETTER_IAM_DEBUG` is set (a JavaScript `Error` that is neither
    /// an `IamError` nor a system error, such as `TypeError: fetch failed`).
    pub fn unknown(message: impl Into<String>, debug: impl Into<String>) -> Self {
        Self(Box::new(CliFailure {
            error: IamError::new("", message),
            hint: None,
            exit_status: None,
            known: false,
            debug: Some(debug.into()),
        }))
    }

    pub fn code(&self) -> &str {
        &self.error.code
    }

    pub fn message(&self) -> &str {
        &self.error.message
    }

    /// The `code` the binary reports, or None for an unknown error (`errorCode`).
    pub fn error_code(&self) -> Option<&str> {
        (self.known || !self.error.code.is_empty()).then_some(self.error.code.as_str())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}

impl std::error::Error for CliError {}

impl From<IamError> for CliError {
    fn from(error: IamError) -> Self {
        Self(Box::new(CliFailure {
            error,
            hint: None,
            exit_status: None,
            known: true,
            debug: None,
        }))
    }
}

/// A usage mistake (unknown flag, missing value, bad number): the binary exits with status 2 for these
/// (`usageError`).
pub fn usage_error(message: impl Into<String>, hint: Option<&str>) -> CliError {
    CliError::new("INVALID_ARGUMENT", message, hint)
}

/// Codes that mean the command line itself was wrong, so the binary exits 2 (like most Unix tools) (`usageCodes`).
pub const USAGE_CODES: [&str; 2] = ["INVALID_ARGUMENT", "INVALID_COMMAND"];

/// A Node.js system error from a file operation (`ENOENT: no such file or directory, open '/x'`), which the binary
/// reports with its code like Node does.
pub fn io_error(error: &std::io::Error, syscall: &str, path: &std::path::Path) -> CliError {
    use std::io::ErrorKind;
    let (code, description) = match error.kind() {
        ErrorKind::NotFound => ("ENOENT", "no such file or directory"),
        ErrorKind::AlreadyExists => ("EEXIST", "file already exists"),
        ErrorKind::PermissionDenied => ("EACCES", "permission denied"),
        ErrorKind::IsADirectory => ("EISDIR", "illegal operation on a directory"),
        ErrorKind::NotADirectory => ("ENOTDIR", "not a directory"),
        ErrorKind::DirectoryNotEmpty => ("ENOTEMPTY", "directory not empty"),
        ErrorKind::InvalidInput | ErrorKind::InvalidFilename => ("EINVAL", "invalid argument"),
        ErrorKind::StorageFull => ("ENOSPC", "no space left on device"),
        ErrorKind::ReadOnlyFilesystem => ("EROFS", "read-only file system"),
        ErrorKind::ResourceBusy => ("EBUSY", "resource busy or locked"),
        ErrorKind::InvalidData => ("EILSEQ", "illegal byte sequence"),
        _ => ("EIO", "i/o error"),
    };
    let mut failure = CliError::new(
        code,
        format!("{code}: {description}, {syscall} '{}'", path.display()),
        None,
    );
    failure.error.status = 500;
    failure
}

/// Levenshtein distance, for "did you mean" suggestions on commands and flags.
fn distance(a: &[char], b: &[char]) -> usize {
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut previous = row[0];
        row[0] = i;
        for j in 1..=b.len() {
            let current = row[j];
            row[j] = (row[j] + 1)
                .min(row[j - 1] + 1)
                .min(previous + usize::from(a[i - 1] != b[j - 1]));
            previous = current;
        }
    }
    row[b.len()]
}

/// The closest candidates to a mistyped name: prefix matches first, then anything within two edits (`suggest`).
pub fn suggest<'a>(
    input: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<String> {
    let needle = input.to_lowercase();
    let needle_chars: Vec<char> = needle.chars().collect();
    let mut seen: Vec<&str> = Vec::new();
    let mut scored: Vec<(String, usize)> = Vec::new();
    for name in candidates {
        if seen.contains(&name) {
            continue;
        }
        seen.push(name);
        let lower = name.to_lowercase();
        if lower == needle {
            continue;
        }
        let score = if lower.starts_with(&needle) || needle.starts_with(&lower) {
            0
        } else {
            distance(&needle_chars, &lower.chars().collect::<Vec<_>>())
        };
        if score <= 2.max(needle_chars.len() / 4) {
            scored.push((name.to_owned(), score));
        }
    }
    scored.sort_by(|a, b| match a.1.cmp(&b.1) {
        Ordering::Equal => locale_compare(&a.0, &b.0),
        other => other,
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(name, _)| name)
        .collect()
}

/// `" Did you mean X or Y?"` or an empty string (`didYouMean`).
pub fn did_you_mean<'a>(
    input: &str,
    candidates: impl IntoIterator<Item = &'a str>,
    prefix: &str,
) -> String {
    let matches: Vec<String> = suggest(input, candidates, 3)
        .into_iter()
        .map(|name| format!("{prefix}{name}"))
        .collect();
    match matches.len() {
        0 => String::new(),
        1 => format!(" Did you mean {}?", matches[0]),
        n => format!(
            " Did you mean {} or {}?",
            matches[..n - 1].join(", "),
            matches[n - 1]
        ),
    }
}
