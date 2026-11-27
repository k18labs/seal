# Performance

Hash input is processed using a fixed 65,536-byte buffer. A Windows x86-64 release executable measured 732,672 bytes using Rust 1.96.0, the locked dependency set, and the release profile in `Cargo.toml`. This is one local build measurement, not a reproducible-build claim. No startup-time, RSS, or throughput benchmark has been run. Reproduce measurements with a recorded OS, CPU, compiler, build profile, input size, and baseline tool before making comparisons.
