//! The process's own IO (`processIO` in index.ts): stdout, stderr, the process environment, standard input, and
//! prompts when both stdin and stderr are terminals.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::sync::Arc;

use crate::errors::{CliError, CliResult};
use crate::framework::{CliIo, process_env};

/// Puts the terminal into raw mode (no echo, byte by byte) until dropped.
struct RawMode {
    #[cfg(unix)]
    saved: Option<libc::termios>,
    #[cfg(windows)]
    saved: Option<(windows_sys::Win32::Foundation::HANDLE, u32)>,
}

impl RawMode {
    #[cfg(unix)]
    fn enter() -> Self {
        // SAFETY: tcgetattr/tcsetattr on standard input with a zeroed, then filled, termios struct.
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut term) != 0 {
                return Self { saved: None };
            }
            let saved = term;
            term.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
            term.c_iflag &= !(libc::IXON | libc::ICRNL);
            term.c_cc[libc::VMIN] = 1;
            term.c_cc[libc::VTIME] = 0;
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term);
            Self { saved: Some(saved) }
        }
    }

    #[cfg(windows)]
    fn enter() -> Self {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
            GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
        };
        // SAFETY: console mode calls on the process's standard input handle.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return Self { saved: None };
            }
            SetConsoleMode(
                handle,
                mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            );
            Self {
                saved: Some((handle, mode)),
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn enter() -> Self {
        Self {}
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(saved) = self.saved {
            // SAFETY: restores the termios read in `enter`.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved);
            }
        }
        #[cfg(windows)]
        if let Some((handle, mode)) = self.saved {
            // SAFETY: restores the console mode read in `enter`.
            unsafe {
                windows_sys::Win32::System::Console::SetConsoleMode(handle, mode);
            }
        }
    }
}

/// A prompt whose answer is not echoed: Enter or end-of-transmission finishes, Ctrl+C cancels, Backspace and Delete
/// edit.
fn hidden_prompt(question: &str) -> CliResult<String> {
    eprint!("{question}");
    let _ = std::io::stderr().flush();
    let raw = RawMode::enter();
    let mut value = String::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut stdin = std::io::stdin().lock();
    let mut byte = [0u8; 1];
    let result = loop {
        match stdin.read(&mut byte) {
            Ok(0) => break Ok(value),
            Ok(_) => {}
            Err(error) => {
                break Err(CliError::unknown(
                    "Reading the terminal failed",
                    error.to_string(),
                ));
            }
        }
        let code = byte[0];
        if pending.is_empty() {
            if code == 13 || code == 10 || code == 4 {
                break Ok(value);
            }
            if code == 3 {
                break Err(CliError::new("CANCELLED", "Cancelled", None));
            }
            if code == 127 || code == 8 {
                value.pop();
                continue;
            }
            if code < 32 {
                continue;
            }
        }
        pending.push(code);
        match std::str::from_utf8(&pending) {
            Ok(text) => {
                value.push_str(text);
                pending.clear();
            }
            Err(error) if error.error_len().is_some() => pending.clear(),
            Err(_) => {}
        }
    };
    drop(raw);
    eprintln!();
    result
}

fn visible_prompt(question: &str) -> CliResult<String> {
    eprint!("{question}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| CliError::unknown("Reading the terminal failed", error.to_string()))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// The process's own IO: stdout, stderr, the process environment, and prompts when both stdin and stderr are
/// terminals (`processIO`).
pub fn process_io() -> CliIo {
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    CliIo {
        out: Arc::new(|message: &str| {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{message}");
        }),
        err: Some(Arc::new(|message: &str| eprintln!("{message}"))),
        env: process_env(),
        cwd: std::env::current_dir().ok(),
        prompt: interactive.then(|| {
            Arc::new(|question: String, hidden: bool| {
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || {
                        if hidden {
                            hidden_prompt(&question)
                        } else {
                            visible_prompt(&question)
                        }
                    })
                    .await
                    .map_err(|error| {
                        CliError::unknown("Reading the terminal failed", error.to_string())
                    })?
                }) as futures::future::BoxFuture<'static, CliResult<String>>
            }) as crate::framework::PromptFn
        }),
        stdin: Some(Arc::new(|| {
            Box::pin(async move {
                tokio::task::spawn_blocking(|| {
                    let mut bytes = Vec::new();
                    std::io::stdin().read_to_end(&mut bytes).map_err(|error| {
                        CliError::unknown("Reading standard input failed", error.to_string())
                    })?;
                    Ok(String::from_utf8_lossy(&bytes).into_owned())
                })
                .await
                .map_err(|error| {
                    CliError::unknown("Reading standard input failed", error.to_string())
                })?
            })
        })),
        fetch: None,
    }
}
