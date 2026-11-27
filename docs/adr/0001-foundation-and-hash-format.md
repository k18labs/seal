# ADR 0001: single Rust crate and streamed hash command

- **Status:** Accepted for the initial implementation
- **Date:** 2026-11-26

## Context

Seal needs a small reusable verification library and a CLI, while avoiding a premature multi-crate workspace. The first usable capability is file hashing. SHA-256 is required for compatibility; BLAKE3 is an optional speed-oriented choice.

## Decision

Use one Rust package with `src/lib.rs` for reusable logic and `src/main.rs` for CLI parsing and presentation. Hash regular files in fixed 64 KiB chunks using the established `sha2` and `blake3` crates. Use lowercase hex. Make SHA-256 the command default and enable BLAKE3 through a default-on Cargo feature that can be removed at build time. JSON mode uses `serde_json`.

## Consequences

The initial binary has CLI and serialization dependencies beyond the digest library. No manifest, signature, key encoding, or trust format is defined. The path metadata check followed by open is not race-resistant. Those capabilities require later design decisions and stronger filesystem controls.
