# Seal Roadmap Implementation Plan

**Goal:** Implement the concrete, non-release-decision items in `ROADMAP.md` while preserving the v1 wire formats and trust model.

**Architecture:** Extend the existing Clap CLI and manifest library without changing the single-crate layout. Keep manifests canonical and bounded, progress on stderr, JSON on stdout, and trusted-key selection explicit. Add documentation and workflow examples that describe only behavior that exists.

**Tech Stack:** Rust 2024, Clap 4, serde/serde_json, existing manifest/tree/hash modules, GitHub Actions, and Python benchmark scripts.

**Spec:** `ROADMAP.md`, `SPEC.md`, `docs/CLI.md`, and `docs/MANIFEST_FORMAT.md`.

## Global Constraints

- Keep cryptography in established libraries; never implement primitives.
- Keep file processing streamed and bounded in memory.
- Keep v1 manifest/signature formats strict, versioned, and unchanged.
- Do not trust public keys supplied beside an artifact.
- Keep progress off stdout and JSON machine-readable.
- Do not create a production GitHub Release or `v1.0.0` tag as part of code implementation.

## Review Focus

- Oversized or noncanonical manifests must be rejected before unbounded allocation.
- Progress output must not corrupt stdout JSON or alter verification results.
- Manifest comparison must not claim it verifies files on disk.
- Generated completions must reflect the actual command tree and supported shells.
- CI examples must obtain trusted keys independently and fail closed.
- Benchmark metadata must identify the source revision and platform; results must not be presented as cross-platform proof if one platform failed.

---

### Task 1: Manifest inspection and comparison

**Files:** `src/main.rs`, `src/manifest.rs`, `tests/manifest_cli.rs`, `docs/CLI.md`.

- [ ] Add tests for deterministic inspect output, same/different manifest comparison, and rejection of malformed or oversized inputs.
- [ ] Run the focused integration tests and confirm they fail because the commands are missing.
- [ ] Implement bounded manifest loading plus read-only `manifest inspect` and `manifest compare` commands with stable text and versioned JSON results.
- [ ] Run the focused tests, then `cargo test --locked`.

### Task 2: Manifest progress reporting

**Files:** `src/tree.rs`, `src/main.rs`, `tests/manifest_cli.rs`, `docs/CLI.md`.

- [ ] Add tests proving `--progress` writes only to stderr and does not change successful/failing JSON output.
- [ ] Run the focused tests and confirm they fail because `--progress` is not accepted.
- [ ] Add bounded progress callbacks for create and verify; report completed files and bytes, without buffering file contents or changing manifest output.
- [ ] Run focused tests and `cargo test --locked`.

### Task 3: CLI completions and output contract

**Files:** `Cargo.toml`, `Cargo.lock`, `src/main.rs`, `tests/hash_cli.rs`, `tests/manifest_cli.rs`, `docs/CLI.md`.

- [ ] Add tests for completion output for Bash, Zsh, Fish, and PowerShell and for the JSON schema version.
- [ ] Run focused tests and confirm they fail before implementation.
- [ ] Add completion generation from the current Clap command tree; version JSON output and document exact JSON-capable commands and exit codes.
- [ ] Run focused tests, `cargo fmt --all -- --check`, `cargo test --locked`, and `cargo clippy --all-targets --all-features --locked -- -D warnings`.

### Task 4: Release and trust workflows

**Files:** `docs/RELEASE_CHECKLIST.md`, `docs/KEY_ROTATION.md`, `docs/INTEGRATION.md`, `examples/github-actions/*`, `README.md`, `ROADMAP.md`.

- [ ] Add a release checklist with tag/version, CI, checksum, provenance, independent key distribution, and known-limitation checks.
- [ ] Add a key rotation/recovery guide that never treats a bundled key as trusted.
- [ ] Add copy-ready GitHub Actions examples for hashing and signed-manifest verification, pinned to a reviewed Seal ref and expected public-key fingerprint.
- [ ] Document GitHub release archives as the initial binary installation channel; keep package-manager support deferred until demand is known.
- [ ] Validate example YAML and run its local commands against a temporary signed test tree.

### Task 5: Benchmark evidence and scaling decision

**Files:** `scripts/bench_operations.py`, `.github/workflows/benchmark.yml`, `docs/PERFORMANCE.md`, `ROADMAP.md`.

- [ ] Add source revision, target, build profile, and complete run settings to benchmark metadata.
- [ ] Make benchmark measurement portable across Linux, macOS, and Windows, with bounded output and recorded peak memory.
- [ ] Add a manual Linux/macOS/Windows benchmark matrix and run it; record results only for successful jobs and state remaining platform gaps.
- [ ] Use measurements to decide whether bounded parallel hashing has evidence of benefit; otherwise record why it remains deferred.

### Task 6: Resolve conditional roadmap proposals

**Files:** `docs/superpowers/specs/2026-11-27-seal-future-format-evaluation.md`, `ROADMAP.md`.

- [ ] Record a decision that v1 manifests remain exact-tree and metadata-free; any exclusions, metadata, or snapshot support requires a separate versioned format design.
- [ ] Record that a built-in trust bundle is deferred unless users need it; explicit trusted-key input remains the current behavior.
- [ ] Reconcile every roadmap checkbox with implemented evidence, a completed design decision, or an explicit maintainer decision still pending.

### Final verification

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo test --locked`.
- [ ] Run `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [ ] Review the full diff and confirm no production release/tag was created.
- [ ] Push the implementation branch and fast-forward both `main` and `master` after checks pass.
