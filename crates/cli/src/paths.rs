//! `path.resolve` and `os.homedir` as Node.js computes them.

use std::path::{Component, Path, PathBuf};

/// `path.resolve(base, value)`: `value` against `base`, with `.` and `..` segments removed lexically.
pub fn resolve_path(base: &Path, value: &Path) -> PathBuf {
    let joined = base.join(value);
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let root_only = matches!(
                    out.components().next_back(),
                    None | Some(Component::RootDir | Component::Prefix(_))
                );
                if !root_only {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `os.homedir()`: `HOME` (or `USERPROFILE` on Windows) of this process.
pub fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().filter(|path| !path.as_os_str().is_empty())
}

/// A path as a string, the way Node prints it.
pub fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
