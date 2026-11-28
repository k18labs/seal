#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::Zeroizing;

use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
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
        /// Read the passphrase from this file instead of prompting.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
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
        /// Read the passphrase from this file instead of prompting.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
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
    /// Create, sign, or verify a deterministic directory manifest.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Generate a shell completion script.
    Completions { shell: CompletionShell },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell")]
    PowerShell,
}

#[derive(Subcommand)]
enum ManifestCommand {
    /// Create a deterministic manifest for a directory tree.
    Create {
        /// Directory tree to scan.
        root: PathBuf,
        /// Output manifest path, outside the scanned root.
        #[arg(long)]
        output: PathBuf,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
        /// Report scan progress to stderr.
        #[arg(long)]
        progress: bool,
    },
    /// Inspect a canonical manifest without checking files on disk.
    Inspect {
        /// Manifest file to inspect.
        manifest: PathBuf,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Compare two canonical manifests without checking files on disk.
    Compare {
        /// First manifest to compare.
        left: PathBuf,
        /// Second manifest to compare.
        right: PathBuf,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Sign a manifest using an Ed25519 key.
    Sign {
        /// Manifest to sign.
        manifest: PathBuf,
        /// OpenSSH private key.
        #[arg(long)]
        key: PathBuf,
        /// Detached signature output path.
        #[arg(long)]
        output: PathBuf,
        /// Read the passphrase from this file instead of prompting.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Verify a signed manifest and the exact directory file set.
    Verify {
        /// Manifest to verify.
        manifest: PathBuf,
        /// Directory tree root.
        #[arg(long)]
        root: PathBuf,
        /// Detached signature record.
        #[arg(long)]
        signature: PathBuf,
        /// Public key obtained through a trusted channel.
        #[arg(long)]
        public_key: PathBuf,
        /// Emit one JSON object on stdout.
        #[arg(long)]
        json: bool,
        /// Report scan progress to stderr.
        #[arg(long)]
        progress: bool,
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
    schema_version: u8,
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

#[derive(Serialize)]
struct ManifestVerifyOutput {
    schema_version: u8,
    verified: bool,
    signature_valid: Option<bool>,
    signer_trusted: Option<bool>,
    integrity_valid: Option<bool>,
    signer_fingerprint: Option<String>,
    matched_files: u64,
    missing_files: u64,
    modified_files: u64,
    unexpected_files: u64,
    errors: Vec<VerifyError>,
}

#[derive(Serialize)]
struct ManifestEntryOutput<'a> {
    path: &'a str,
    size: u64,
    digest: &'a str,
}

#[derive(Serialize)]
struct ManifestInspectOutput<'a> {
    schema_version: u8,
    manifest_version: u8,
    algorithm: &'a str,
    files: usize,
    total_bytes: u64,
    entries: Vec<ManifestEntryOutput<'a>>,
}

#[derive(Serialize)]
struct ManifestCompareOutput {
    schema_version: u8,
    left_manifest_version: u8,
    right_manifest_version: u8,
    left_algorithm: String,
    right_algorithm: String,
    identical: bool,
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
    verifies_files_on_disk: bool,
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
        Command::Completions { shell } => {
            let shell = match shell {
                CompletionShell::Bash => clap_complete::aot::Shell::Bash,
                CompletionShell::Zsh => clap_complete::aot::Shell::Zsh,
                CompletionShell::Fish => clap_complete::aot::Shell::Fish,
                CompletionShell::PowerShell => clap_complete::aot::Shell::PowerShell,
            };
            clap_complete::generate(shell, &mut Cli::command(), "seal", &mut std::io::stdout());
            Ok(())
        }
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
            let digest = if path == std::path::Path::new("-") {
                seal::hash::hash_reader(&mut std::io::stdin().lock(), algorithm)
            } else {
                seal::hash::hash_file(&path, algorithm)
            }
            .map_err(|error| {
                let code = if matches!(error, seal::hash::HashError::AlgorithmUnavailable) {
                    7
                } else {
                    5
                };
                (code, error.to_string())
            })?;
            let output = HashOutput {
                schema_version: 1,
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
        Command::Keygen {
            out,
            passphrase_file,
        } => {
            let passphrase = load_passphrase(passphrase_file.as_deref(), true)?;
            let fingerprint =
                seal::signature::keygen(&out, passphrase.as_bytes()).map_err(signature_error)?;
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
        Command::Sign {
            path,
            key,
            output,
            passphrase_file,
        } => {
            let passphrase = load_passphrase(passphrase_file.as_deref(), false)?;
            let signer = seal::signature::sign_file(&path, &key, &output, passphrase.as_bytes())
                .map_err(signature_error)?;
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
        Command::Manifest { command } => match command {
            ManifestCommand::Create {
                root,
                output,
                json,
                progress,
            } => {
                let mut last_progress = std::time::Instant::now();
                let manifest = if progress {
                    seal::tree::create_manifest_with_progress(&root, &output, |state| {
                        if last_progress.elapsed() >= std::time::Duration::from_millis(500) {
                            eprintln!(
                                "progress: {} files, {} bytes read",
                                state.files_seen, state.bytes_read
                            );
                            last_progress = std::time::Instant::now();
                        }
                    })
                } else {
                    seal::tree::create_manifest(&root, &output)
                }
                .map_err(tree_error)?;
                if progress {
                    eprintln!(
                        "progress complete: {} files, {} bytes read",
                        manifest.files.len(),
                        manifest.files.iter().map(|entry| entry.size).sum::<u64>()
                    );
                }
                if json {
                    #[derive(Serialize)]
                    struct Created<'a> {
                        schema_version: u8,
                        created: bool,
                        files: usize,
                        manifest: &'a str,
                    }
                    let rendered = output.to_string_lossy();
                    println!(
                        "{}",
                        serde_json::to_string(&Created {
                            schema_version: 1,
                            created: true,
                            files: manifest.files.len(),
                            manifest: &rendered,
                        })
                        .map_err(|error| (5, format!("could not encode JSON: {error}")))?
                    );
                } else {
                    println!("MANIFEST CREATED");
                    println!("Files: {}", manifest.files.len());
                    println!("Manifest: {}", escape_terminal(&output.to_string_lossy()));
                }
                Ok(())
            }
            ManifestCommand::Inspect { manifest, json } => {
                let model = read_manifest(&manifest)?;
                let total_bytes = model.files.iter().map(|entry| entry.size).sum();
                if json {
                    let output = ManifestInspectOutput {
                        schema_version: 1,
                        manifest_version: model.version,
                        algorithm: &model.algorithm,
                        files: model.files.len(),
                        total_bytes,
                        entries: model
                            .files
                            .iter()
                            .map(|entry| ManifestEntryOutput {
                                path: &entry.path,
                                size: entry.size,
                                digest: &entry.digest,
                            })
                            .collect(),
                    };
                    println!(
                        "{}",
                        serde_json::to_string(&output)
                            .map_err(|error| (5, format!("could not encode JSON: {error}")))?
                    );
                } else {
                    println!("MANIFEST");
                    println!("Version: {}", model.version);
                    println!("Algorithm: {}", model.algorithm);
                    println!("Files: {}", model.files.len());
                    println!("Total bytes: {total_bytes}");
                    println!(
                        "NOTE: This inspects manifest data; it does not verify files on disk."
                    );
                    for entry in &model.files {
                        println!(
                            "{}\t{}\t{}",
                            entry.size,
                            entry.digest,
                            escape_terminal(&entry.path)
                        );
                    }
                }
                Ok(())
            }
            ManifestCommand::Compare { left, right, json } => {
                let left_model = read_manifest(&left)?;
                let right_model = read_manifest(&right)?;
                let output = compare_manifests(&left_model, &right_model);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&output)
                            .map_err(|error| (5, format!("could not encode JSON: {error}")))?
                    );
                } else {
                    println!(
                        "{}",
                        if output.identical {
                            "IDENTICAL MANIFEST CONTENTS"
                        } else {
                            "MANIFESTS DIFFER"
                        }
                    );
                    println!("NOTE: Comparing manifests does not verify files on disk.");
                    for path in &output.added {
                        println!("+ {}", escape_terminal(path));
                    }
                    for path in &output.removed {
                        println!("- {}", escape_terminal(path));
                    }
                    for path in &output.changed {
                        println!("~ {}", escape_terminal(path));
                    }
                }
                Ok(())
            }
            ManifestCommand::Sign {
                manifest,
                key,
                output,
                passphrase_file,
            } => {
                let passphrase = load_passphrase(passphrase_file.as_deref(), false)?;
                let signer =
                    seal::signature::sign_manifest(&manifest, &key, &output, passphrase.as_bytes())
                        .map_err(signature_error)?;
                println!("SIGNED");
                println!("Object: manifest");
                println!("Manifest: {}", escape_terminal(&manifest.to_string_lossy()));
                println!("Signature: {}", escape_terminal(&output.to_string_lossy()));
                println!("Signer: {signer}");
                Ok(())
            }
            ManifestCommand::Verify {
                manifest,
                root,
                signature,
                public_key,
                json,
                progress,
            } => {
                let outputs_inside = seal::tree::output_is_inside_root(&root, &manifest)
                    .map_err(tree_error)?
                    || seal::tree::output_is_inside_root(&root, &signature).map_err(tree_error)?;
                if outputs_inside {
                    return Err(tree_error(seal::tree::TreeError::OutputInsideRoot));
                }
                let (signer, manifest_model) = match seal::signature::verify_manifest_signature(
                    &manifest,
                    &signature,
                    &public_key,
                ) {
                    Ok(result) => result,
                    Err(error) if json => {
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
                        let output = ManifestVerifyOutput {
                            schema_version: 1,
                            verified: false,
                            signature_valid,
                            signer_trusted,
                            integrity_valid,
                            signer_fingerprint: None,
                            matched_files: 0,
                            missing_files: 0,
                            modified_files: 0,
                            unexpected_files: 0,
                            errors: vec![VerifyError {
                                exit_code: error.exit_code(),
                                message: error.to_string(),
                            }],
                        };
                        println!(
                            "{}",
                            serde_json::to_string(&output).map_err(|encode_error| (
                                5,
                                format!("could not encode JSON: {encode_error}")
                            ))?
                        );
                        eprintln!("seal: {error}");
                        return Err((error.exit_code(), String::new()));
                    }
                    Err(error) => return Err(signature_error(error)),
                };
                let mut last_progress = std::time::Instant::now();
                let mut final_progress = seal::tree::ScanProgress::default();
                let verification = if progress {
                    seal::tree::verify_directory_with_progress(&root, &manifest_model, |state| {
                        final_progress = state;
                        if last_progress.elapsed() >= std::time::Duration::from_millis(500) {
                            eprintln!(
                                "progress: {} files, {} bytes read",
                                state.files_seen, state.bytes_read
                            );
                            last_progress = std::time::Instant::now();
                        }
                    })
                } else {
                    seal::tree::verify_directory(&root, &manifest_model)
                };
                if progress
                    && matches!(
                        &verification,
                        Ok(_) | Err(seal::tree::TreeError::IntegrityMismatch(_))
                    )
                {
                    eprintln!(
                        "progress complete: {} files, {} bytes read",
                        final_progress.files_seen, final_progress.bytes_read
                    );
                }
                match verification {
                    Ok(report) => {
                        if json {
                            let output = ManifestVerifyOutput {
                                schema_version: 1,
                                verified: true,
                                signature_valid: Some(true),
                                signer_trusted: Some(true),
                                integrity_valid: Some(true),
                                signer_fingerprint: Some(signer),
                                matched_files: report.matched_files,
                                missing_files: report.missing_files,
                                modified_files: report.modified_files,
                                unexpected_files: report.unexpected_files,
                                errors: Vec::new(),
                            };
                            println!(
                                "{}",
                                serde_json::to_string(&output).map_err(|error| (
                                    5,
                                    format!("could not encode JSON: {error}")
                                ))?
                            );
                        } else {
                            println!("VERIFIED");
                            println!("Manifest: {}", escape_terminal(&manifest.to_string_lossy()));
                            println!("Files: {}", report.matched_files);
                            println!("Signer: {signer}");
                        }
                        Ok(())
                    }
                    Err(seal::tree::TreeError::IntegrityMismatch(report)) => {
                        let error = seal::tree::TreeError::IntegrityMismatch(report.clone());
                        if json {
                            let output = ManifestVerifyOutput {
                                schema_version: 1,
                                verified: false,
                                signature_valid: Some(true),
                                signer_trusted: Some(true),
                                integrity_valid: Some(false),
                                signer_fingerprint: Some(signer),
                                matched_files: report.matched_files,
                                missing_files: report.missing_files,
                                modified_files: report.modified_files,
                                unexpected_files: report.unexpected_files,
                                errors: vec![VerifyError {
                                    exit_code: 1,
                                    message: error.to_string(),
                                }],
                            };
                            println!(
                                "{}",
                                serde_json::to_string(&output).map_err(|encode_error| (
                                    5,
                                    format!("could not encode JSON: {encode_error}")
                                ))?
                            );
                            eprintln!("seal: {error}");
                            Err((1, String::new()))
                        } else {
                            Err(tree_error(error))
                        }
                    }
                    Err(error) if json => {
                        let output = ManifestVerifyOutput {
                            schema_version: 1,
                            verified: false,
                            signature_valid: Some(true),
                            signer_trusted: Some(true),
                            integrity_valid: None,
                            signer_fingerprint: Some(signer),
                            matched_files: 0,
                            missing_files: 0,
                            modified_files: 0,
                            unexpected_files: 0,
                            errors: vec![VerifyError {
                                exit_code: tree_error_code(&error),
                                message: error.to_string(),
                            }],
                        };
                        println!(
                            "{}",
                            serde_json::to_string(&output).map_err(|encode_error| (
                                5,
                                format!("could not encode JSON: {encode_error}")
                            ))?
                        );
                        eprintln!("seal: {error}");
                        Err((tree_error_code(&error), String::new()))
                    }
                    Err(error) => Err(tree_error(error)),
                }
            }
        },
    }
}

fn read_manifest(path: &std::path::Path) -> Result<seal::manifest::Manifest, (u8, String)> {
    let mut file = open_regular_input(path).map_err(|error| {
        let status = if error.kind() == io::ErrorKind::InvalidInput {
            4
        } else {
            5
        };
        (status, format!("could not open manifest: {error}"))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| (5, format!("could not inspect manifest: {error}")))?;
    if !metadata.is_file() {
        return Err((4, "manifest input must be a regular file".to_owned()));
    }
    let max_bytes = seal::manifest::MAX_MANIFEST_BYTES;
    if metadata.len() > max_bytes as u64 {
        return Err((4, "manifest exceeds the 16 MiB input size limit".to_owned()));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| (4, "manifest exceeds the 16 MiB input size limit".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| (5, format!("could not read manifest: {error}")))?;
    if bytes.len() > max_bytes {
        return Err((4, "manifest exceeds the 16 MiB input size limit".to_owned()));
    }
    seal::manifest::Manifest::parse(&bytes).map_err(|error| (4, error.to_string()))
}

fn compare_manifests(
    left: &seal::manifest::Manifest,
    right: &seal::manifest::Manifest,
) -> ManifestCompareOutput {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let (mut left_index, mut right_index) = (0, 0);

    while left_index < left.files.len() || right_index < right.files.len() {
        match (left.files.get(left_index), right.files.get(right_index)) {
            (Some(left_entry), Some(right_entry)) => {
                match left_entry.path.as_bytes().cmp(right_entry.path.as_bytes()) {
                    std::cmp::Ordering::Less => {
                        removed.push(left_entry.path.clone());
                        left_index += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        added.push(right_entry.path.clone());
                        right_index += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        if left_entry.size != right_entry.size
                            || left_entry.digest != right_entry.digest
                        {
                            changed.push(left_entry.path.clone());
                        }
                        left_index += 1;
                        right_index += 1;
                    }
                }
            }
            (Some(left_entry), None) => {
                removed.push(left_entry.path.clone());
                left_index += 1;
            }
            (None, Some(right_entry)) => {
                added.push(right_entry.path.clone());
                right_index += 1;
            }
            (None, None) => break,
        }
    }

    let identical = added.is_empty()
        && removed.is_empty()
        && changed.is_empty()
        && left.version == right.version
        && left.algorithm == right.algorithm;
    ManifestCompareOutput {
        schema_version: 1,
        left_manifest_version: left.version,
        right_manifest_version: right.version,
        left_algorithm: left.algorithm.clone(),
        right_algorithm: right.algorithm.clone(),
        identical,
        added,
        removed,
        changed,
        verifies_files_on_disk: false,
    }
}

fn signature_error(error: seal::signature::SignatureError) -> (u8, String) {
    (error.exit_code(), error.to_string())
}

fn load_passphrase(
    path: Option<&std::path::Path>,
    confirm: bool,
) -> Result<Zeroizing<String>, (u8, String)> {
    let value = if let Some(path) = path {
        let mut file = open_regular_input(path).map_err(|e| {
            let status = if e.kind() == io::ErrorKind::InvalidInput {
                4
            } else {
                5
            };
            (status, e.to_string())
        })?;
        let metadata = file.metadata().map_err(|e| (5, e.to_string()))?;
        if !metadata.is_file() || metadata.len() > 1024 {
            return Err((
                4,
                "passphrase file must be a regular file of at most 1024 bytes".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(1025);
        file.by_ref()
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|e| (5, e.to_string()))?;
        if bytes.len() > 1024 {
            return Err((4, "passphrase file must contain at most 1024 bytes".into()));
        }
        let raw = Zeroizing::new(bytes);
        let raw = raw
            .strip_suffix(b"\r\n")
            .or_else(|| raw.strip_suffix(b"\n"))
            .unwrap_or(&raw);
        if raw.contains(&b'\n') || raw.contains(&b'\r') {
            return Err((4, "passphrase file must contain one line".into()));
        }
        Zeroizing::new(
            String::from_utf8(raw.to_vec())
                .map_err(|_| (4, "passphrase file must be UTF-8".into()))?,
        )
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Passphrase: ")
                .map_err(|e| (5, format!("could not read passphrase: {e}")))?,
        )
    };
    if confirm && path.is_none() {
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .map_err(|e| (5, format!("could not read passphrase: {e}")))?,
        );
        if *value != *second {
            return Err((4, "passphrases do not match".into()));
        }
    }
    if !(12..=1024).contains(&value.len()) {
        return Err((4, "passphrase must be 12 to 1024 UTF-8 bytes".into()));
    }
    Ok(value)
}

fn open_regular_input(path: &Path) -> io::Result<File> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Avoid blocking if a special file replaces the path after the metadata check.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    Ok(file)
}

fn tree_error(error: seal::tree::TreeError) -> (u8, String) {
    (tree_error_code(&error), error.to_string())
}

fn tree_error_code(error: &seal::tree::TreeError) -> u8 {
    use seal::tree::TreeError;
    match error {
        TreeError::Io(_) => 5,
        TreeError::OutputInsideRoot
        | TreeError::ResourceLimit(_)
        | TreeError::UnsupportedObject(_)
        | TreeError::Manifest(_) => 4,
        TreeError::IntegrityMismatch(_) => 1,
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
