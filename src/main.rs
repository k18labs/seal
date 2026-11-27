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
    /// Generate an Ed25519 key pair.
    Keygen {
        /// Output path for the private key. The public key is written to PATH.pub.
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect or fingerprint a public key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Sign a regular file and write a detached signature.
    Sign {
        /// File to sign.
        path: PathBuf,
        /// OpenSSH private key.
        #[arg(long)]
        key: PathBuf,
        /// Signature output path; must not already exist.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a detached signature using an explicitly selected public key.
    Verify {
        /// File to verify.
        path: PathBuf,
        /// Detached signature record.
        #[arg(long)]
        signature: PathBuf,
        /// Public key obtained through a trusted channel.
        #[arg(long)]
        public_key: PathBuf,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Print a public key's SHA-256 fingerprint.
    Fingerprint {
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Inspect a public key's algorithm and fingerprint.
    Inspect {
        #[arg(long)]
        public_key: PathBuf,
    },
}

#[derive(Serialize)]
struct HashOutput {
    algorithm: &'static str,
    digest: String,
    path: String,
}

#[derive(Serialize)]
struct VerifyOutput {
    schema_version: u8,
    verified: bool,
    signature_valid: Option<bool>,
    signer_trusted: Option<bool>,
    integrity_valid: Option<bool>,
    signer_fingerprint: Option<String>,
    errors: Vec<VerifyError>,
}

#[derive(Serialize)]
struct VerifyError {
    exit_code: u8,
    message: String,
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => match run(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err((code, error)) => {
                if !error.is_empty() {
                    eprintln!("seal: {error}");
                }
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
        Command::Keygen { out } => {
            let fingerprint = seal::signature::keygen(&out).map_err(signature_error)?;
            println!("Ed25519 key pair created.");
            println!("Private key: {}", escape_terminal(&out.to_string_lossy()));
            let mut public = out.as_os_str().to_os_string();
            public.push(".pub");
            println!("Public key: {}", escape_terminal(&public.to_string_lossy()));
            println!("Fingerprint: {fingerprint}");
            Ok(())
        }
        Command::Key { command } => match command {
            KeyCommand::Fingerprint { public_key } => {
                let fingerprint =
                    seal::signature::fingerprint(&public_key).map_err(signature_error)?;
                println!("{fingerprint}");
                Ok(())
            }
            KeyCommand::Inspect { public_key } => {
                let (algorithm, fingerprint) =
                    seal::signature::inspect_public_key(&public_key).map_err(signature_error)?;
                println!("Algorithm: {algorithm}");
                println!("Fingerprint: {fingerprint}");
                Ok(())
            }
        },
        Command::Sign { path, key, output } => {
            let signer =
                seal::signature::sign_file(&path, &key, &output).map_err(signature_error)?;
            println!("SIGNED");
            println!("Artifact: {}", escape_terminal(&path.to_string_lossy()));
            println!("Signature: {}", escape_terminal(&output.to_string_lossy()));
            println!("Signer: {signer}");
            Ok(())
        }
        Command::Verify {
            path,
            signature,
            public_key,
            json,
        } => match seal::signature::verify_file(&path, &signature, &public_key) {
            Ok(signer) => {
                let output = VerifyOutput {
                    schema_version: 1,
                    verified: true,
                    signature_valid: Some(true),
                    signer_trusted: Some(true),
                    integrity_valid: Some(true),
                    signer_fingerprint: Some(signer),
                    errors: Vec::new(),
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&output)
                            .map_err(|error| { (5, format!("could not encode JSON: {error}")) })?
                    );
                } else {
                    println!("VERIFIED");
                    println!("Artifact: {}", escape_terminal(&path.to_string_lossy()));
                    println!("Algorithm: SHA-256");
                    println!("Signature: Ed25519 (OpenSSH SSHSIG)");
                    println!(
                        "Signer: {}",
                        output.signer_fingerprint.as_deref().unwrap_or("unknown")
                    );
                }
                Ok(())
            }
            Err(error) => {
                if json {
                    let (signature_valid, signer_trusted, integrity_valid) = match &error {
                        seal::signature::SignatureError::InvalidSignature => {
                            (Some(false), None, None)
                        }
                        seal::signature::SignatureError::UntrustedKey => {
                            (Some(true), Some(false), None)
                        }
                        seal::signature::SignatureError::IntegrityMismatch => {
                            (Some(true), Some(true), Some(false))
                        }
                        _ => (None, None, None),
                    };
                    let output = VerifyOutput {
                        schema_version: 1,
                        verified: false,
                        signature_valid,
                        signer_trusted,
                        integrity_valid,
                        signer_fingerprint: None,
                        errors: vec![VerifyError {
                            exit_code: error.exit_code(),
                            message: error.to_string(),
                        }],
                    };
                    println!(
                        "{}",
                        serde_json::to_string(&output).map_err(|encode_error| {
                            (5, format!("could not encode JSON: {encode_error}"))
                        })?
                    );
                    eprintln!("seal: {error}");
                    Err((error.exit_code(), String::new()))
                } else {
                    Err(signature_error(error))
                }
            }
        },
    }
}

fn signature_error(error: seal::signature::SignatureError) -> (u8, String) {
    (error.exit_code(), error.to_string())
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
