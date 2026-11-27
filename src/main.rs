#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand, error::ErrorKind};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "seal",
    version,
    about = "Offline file integrity tools",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hash a regular file using a streaming digest.
    Hash {
        /// File to hash.
        path: PathBuf,
        /// Digest algorithm.
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print the Seal version.
    Version,
}

#[derive(Serialize)]
struct HashOutput {
    algorithm: &'static str,
    digest: String,
    path: String,
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => match run(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err((code, error)) => {
                eprintln!("seal: {error}");
                ExitCode::from(code)
            }
        },
        Err(error) => {
            let is_help_or_version = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            if is_help_or_version {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(6)
            }
        }
    }
}

fn run(cli: Cli) -> Result<(), (u8, String)> {
    match cli.command {
        Command::Version => {
            println!("seal {}", seal::VERSION);
            Ok(())
        }
        Command::Hash {
            path,
            algorithm,
            json,
        } => {
            let algorithm: seal::hash::Algorithm =
                algorithm.parse().map_err(|error: String| (7, error))?;
            let digest = seal::hash::hash_file(&path, algorithm).map_err(|error| {
                let code = if matches!(error, seal::hash::HashError::AlgorithmUnavailable) {
                    7
                } else {
                    5
                };
                (code, error.to_string())
            })?;
            let output = HashOutput {
                algorithm: algorithm.as_str(),
                digest,
                path: path.to_string_lossy().into_owned(),
            };
            if json {
                let encoded = serde_json::to_string(&output)
                    .map_err(|error| (5, format!("could not encode JSON: {error}")))?;
                println!("{encoded}");
            } else {
                println!("{}  {}", output.digest, escape_terminal(&output.path));
            }
            Ok(())
        }
    }
}

fn escape_terminal(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
mod tests {
    use super::escape_terminal;

    #[test]
    fn terminal_controls_are_escaped() {
        assert_eq!(escape_terminal("a\n\x1b"), "a\\n\\u{1b}");
    }
}
