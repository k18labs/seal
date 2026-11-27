# Seal

Seal is an offline-first Rust command-line tool for checking file and directory integrity. It provides streaming SHA-256 and optional BLAKE3 hashing, Ed25519 signatures for files and deterministic directory manifests, and explicit public-key trust selection. Private signing keys are encrypted at rest.

## Build

Install Rust 1.96.0 or use rustup with the included `rust-toolchain.toml`:

```sh
cargo build --release --locked
```

## Use

```sh
seal hash artifact.tar.gz
seal hash artifact.tar.gz --algorithm sha256
seal hash artifact.tar.gz --algorithm blake3
seal hash artifact.tar.gz --json
seal keygen --out ./keys/release
seal key fingerprint --public-key ./keys/release.pub
seal sign artifact.tar.gz --key ./keys/release --output artifact.tar.gz.seal
seal verify artifact.tar.gz --signature artifact.tar.gz.seal --public-key ./keys/release.pub
seal manifest create ./dist --output release.manifest
seal manifest sign release.manifest --key ./keys/release --output release.manifest.seal
seal manifest verify release.manifest --root ./dist --signature release.manifest.seal --public-key ./keys/release.pub --json
seal version
```

Hashing uses a fixed 64 KiB buffer. Key generation prompts twice for a passphrase; signing prompts once. Use `--passphrase-file FILE` only with a controlled automation secret. JSON output is one object on stdout; errors go to stderr. SHA-256 is the default. An unsigned digest proves integrity only when its expected value comes from a trusted channel. A valid signature does not establish trust unless the supplied public key was obtained through a trusted channel. See [key management](docs/KEY_MANAGEMENT.md), [manifest format](docs/MANIFEST_FORMAT.md), and [signature format](docs/SIGNATURE_FORMAT.md).

To build without optional BLAKE3 support, use `cargo build --no-default-features --locked`.

## Project status

File hashing, encrypted-key signing, and strict signed-manifest verification are implemented. The six-target CI matrix, bounded fuzz smoke, six-target reproducibility comparison, release-candidate builds, SBOM/provenance verification, and comparative benchmarks have run successfully. Concurrent-mutation stress coverage and a qualified external format/security review remain before a version-aligned release-candidate tag. See [ROADMAP.md](ROADMAP.md). This tool is not an antivirus and does not determine whether a file is safe to run.

## License

Apache-2.0. See [LICENSE](LICENSE).
