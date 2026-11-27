# Dependency security notes

Seal enables only the `std`, `ed25519`, and `getrandom` features of `ssh-key`,
with that crate's default features disabled. The lockfile also records optional
crates used by other `ssh-key` features. `cargo audit` scans those locked
packages even when they are not selected for this build, so `.cargo/audit.toml`
ignores the advisories for `rsa` and `crypto-bigint`.

The current feature graph was checked with:

```sh
cargo tree --locked -e features -i rsa
cargo tree --locked -e features -i crypto-bigint
```

Both commands reported no active dependency paths. `cargo deny check` continues
to check advisories in the resolved dependency graph. Recheck and remove these
exceptions if Seal enables additional `ssh-key` features or changes its
dependency graph.

The package MSRV is Rust 1.87.0; CI and the pinned local toolchain use Rust 1.96.0. This floor was raised from 1.85 to select `ctutils` 0.4.8, which resolves the constant-time advisory affecting 0.4.2 in the Argon2id and XChaCha20-Poly1305 dependency graph.

Manifest traversal uses `cap-std` and `cap-fs-ext` for capability-scoped directory access and no-follow opens. Private-key encryption uses `argon2` and `chacha20poly1305`, both with default features disabled, plus `rpassword` for hidden terminal entry. Windows ACL operations use the safe wrappers in `windows-permissions`; the crate contains the platform-specific unsafe OS calls, while first-party code retains `#![forbid(unsafe_code)]`. Review the full active graph with `cargo tree --locked -e features` and rerun `cargo deny check` and `cargo audit` after dependency changes.
