//! `spend-screen`: reads one request on stdin, prints one verdict line on stdout, exits 0.
//!
//! A non-zero exit with no output means the screen could not decide (I/O failure); the bridge
//! treats that as an error and sends nothing to the chain.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let Ok(raw) = spend_screen::read_request(io::stdin().lock()) else {
        return ExitCode::FAILURE;
    };
    let Ok(line) = spend_screen::screen(&raw).to_json_line() else {
        return ExitCode::FAILURE;
    };
    let mut stdout = io::stdout().lock();
    match writeln!(stdout, "{line}").and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
