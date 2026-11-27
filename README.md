# Seal

Seal is an offline-first Rust command-line tool for checking file integrity. This initial implementation provides streaming SHA-256 and optional BLAKE3 hashing. It does **not** yet sign files, manage trusted keys, or verify directories.

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
seal version
```

Hashing uses a fixed 64 KiB buffer. JSON output is one object on stdout; errors go to stderr. SHA-256 is the default. An unsigned digest proves integrity only when its expected value comes from a trusted channel. It does not establish who made a file.

To build without optional BLAKE3 support, use `cargo build --no-default-features --locked`.

## Project status

The current scope is M0 (foundation) and M1 (file hashing). See [ROADMAP.md](ROADMAP.md) for what remains. No security audit or independent format review has been performed. This tool is not an antivirus and does not determine whether a file is safe to run.

## License

Apache-2.0. See [LICENSE](LICENSE).
