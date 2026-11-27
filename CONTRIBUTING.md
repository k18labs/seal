# Contributing

Use the pinned Rust toolchain. Before opening a change, run:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Keep changes scoped, add regression coverage for behavior changes, and update the specification and roadmap when supported behavior changes. Never include private keys or real release credentials in tests or examples.
