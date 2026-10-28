//! Command-line interface for `agwo`.
//!
//! - `args`     : `clap` definitions (`Cli`, `Cmd`, `WslCmd`) and argument parsers
//! - `commands` : execution of each subcommand
//! - `dotenv`   : minimal `.env` loader
//! - `report`   : display of a `RunReport`

mod args;
mod commands;
mod dotenv;
mod report;

use clap::Parser;
use std::process::ExitCode;

/// CLI entry point: loads `.env`, parses arguments, executes the
/// subcommand, and converts errors into an exit code of 2.
pub fn run() -> ExitCode {
    dotenv::load();
    let cli = args::Cli::parse();
    match commands::execute(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error : {err}");
            ExitCode::from(2)
        }
    }
}
