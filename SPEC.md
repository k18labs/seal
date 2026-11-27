# Seal specification, v1 candidate

## Scope

Seal is an offline file-integrity CLI and Rust library. The current candidate implements regular-file hashing (SHA-256 and optional BLAKE3), Ed25519 signing and verification, encrypted private-key storage, deterministic signed manifests, and explicit trusted-key selection.

## Hashing

`seal hash PATH [--algorithm sha256|blake3] [--json]` hashes a regular file with a fixed 65,536-byte buffer. `PATH` equal to `-` reads standard input with the same bounded buffer. SHA-256 is default. Directories and special files are rejected. Output formats are documented in `docs/CLI.md`.

## Keys and signatures

`seal keygen --out PATH` writes encrypted private key material to `PATH` and an OpenSSH Ed25519 public key to `PATH.pub`, failing if either exists. It prompts twice for a 12–1024-byte UTF-8 passphrase; `--passphrase-file FILE` supplies one line for controlled automation. Private-key encryption and platform file permissions are specified in `docs/KEY_MANAGEMENT.md` and `docs/CRYPTOGRAPHY.md`.

`seal sign PATH --key KEY --output SIG` creates a detached Ed25519 SSHSIG in the versioned Seal envelope. `seal verify PATH --signature SIG --public-key PUB [--json]` requires an explicit public key and checks signature, key identity, size, and SHA-256 digest.

## Manifests

`seal manifest create ROOT --output FILE` creates the canonical format in `docs/MANIFEST_FORMAT.md`. `seal manifest sign FILE ...` signs exact manifest bytes. `seal manifest verify FILE --root ROOT --signature SIG --public-key PUB` validates signature and strict exact file-set integrity. Limits, path policy, and filesystem race limitations are documented in the format and threat model documents.

## Exit codes

0 success/help/version; 1 integrity mismatch; 2 invalid signature; 3 invalid or untrusted key; 4 malformed input or policy rejection; 5 I/O or output failure; 6 CLI usage error; 7 unsupported algorithm or format.

This is a candidate specification. Manifest and encrypted-key formats have not received independent review; no stable v1 release should imply such a review occurred.