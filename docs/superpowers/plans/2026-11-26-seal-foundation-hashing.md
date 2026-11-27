# Seal Foundation and Hashing Implementation Plan

**Goal:** Establish a small Rust CLI/library foundation and deliver streaming SHA-256 and optional BLAKE3 file hashing.

**Architecture:** Keep hashing in a reusable library module, keep CLI parsing and output in the binary, and use fixed-size reads. M0/M1 do not claim signature or directory verification support.

**Tech Stack:** Stable Rust 1.96.0, clap, sha2, optional blake3, serde/serde_json for machine output.

**Spec:** `../../../SPEC.md` (initial scope implemented from the development prompt supplied by the user).

## Global Constraints

- “Security takes precedence over performance and binary size.”
- “Use bounded buffers.”
- “Operate offline by default.”
- “No unfinished implementations disguised as working functionality.”
- “Do not implement commands that lack functional behavior.”

## Review Focus

- Empty and large files: digest must be correct and memory independent of file size.
- Directories and special files: reject rather than hash file metadata or block on a stream.
- Read errors: return a failure and never print a success digest.
- Malicious filenames: JSON escaping and terminal-safe presentation.
- Unsupported algorithms and malformed CLI input: fail with stable nonzero status.

---

### Task 1: Rust foundation and project contract

**Files:** `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.gitignore`, `README.md`, `AGENTS.md`, `SPEC.md`, `DESIGN.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`, `docs/*`, `.github/workflows/ci.yml`.

- [x] Establish a single crate with a reusable library and CLI binary.
- [x] Record threat boundaries, format scope, dependency choices, and incomplete milestones.
- [x] Add least-privilege CI using immutable action references and locked builds.

### Task 2: Streaming hash library and CLI

**Files:** `src/lib.rs`, `src/hash.rs`, `src/main.rs`, `tests/hash_cli.rs`.

- [x] Add tests for standard SHA-256 and BLAKE3 vectors, empty and large files, unsupported file types, and JSON output.
- [x] Implement `hash_file(path, algorithm) -> Result<String, HashError>` with a fixed 64 KiB read buffer.
- [x] Implement `seal hash PATH [--algorithm sha256|blake3] [--json]` and `seal version`.
- [x] Run locked formatting, tests, and clippy; record actual results and measured artifact size in the completion report.
