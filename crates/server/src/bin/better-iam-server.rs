//! `better-iam-server`: the standalone Better IAM server, started from a JSON configuration
//! (spec/conformance/CONFIG.md).
//!
//! ```text
//! better-iam-server --config better-iam.json --port 4100 [--host 127.0.0.1] [--conformance]
//! ```
//!
//! With `--conformance` it also answers the test-control endpoints under `/__conformance/`
//! (spec/conformance/CONTROL.md) that the replay runner drives.

use better_iam_server::conformance::{USAGE, parse_args, run};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(message) => {
            if message == USAGE {
                eprintln!("{USAGE}");
            } else {
                eprintln!("{message}\n{USAGE}");
            }
            std::process::exit(2);
        }
    };
    // Large request futures (debug builds especially) need more than the default 2 MiB worker stacks.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(64 * 1024 * 1024)
        .build()
        .expect("a tokio runtime");
    if let Err(error) = runtime.block_on(run(args)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
