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
