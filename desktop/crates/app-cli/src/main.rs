//! `authenticator-cli` entry point; all logic lives in the library.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let stdin = io::stdin();
    let is_terminal = stdin.is_terminal();
    let code = app_cli::run(
        &args,
        &mut stdin.lock(),
        is_terminal,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code)
}
