//! `better-iam`: the Better IAM command line (`better-iam help` lists every command).

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    std::process::exit(better_iam_cli::run_binary(argv, None));
}
