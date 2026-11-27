# Performance

Hash input is processed using a fixed 65,536-byte buffer. The Windows x86-64 release executable measured 1,028,096 bytes using Rust 1.96.0, `ctutils` 0.4.8, and the release profile in `Cargo.toml`; it was built on a Windows ARM64 host using x64 tools. Two clean builds on that host produced identical SHA-256 `0c8ac5cb0bad03339fe08e26995e136622104aa0b9153ce9d57923be07b2fb4c`; the exact evidence is in `docs/evidence/reproducibility-windows-x64-local.json`. This checks one target on one host and is not a cross-host reproducibility result.

The manual benchmark ran on a GitHub hosted Linux x86-64 runner with Rust 1.96.0, five warm-cache repetitions, a 128 MiB input, and a 1,000-file tree. Reported times include process startup; results are a single-run snapshot, not a cross-machine comparison.

| Operation | Median time | Peak child RSS |
| --- | ---: | ---: |
| `seal version` | 0.75 ms | 2,812 KiB |
| File sign | 111.9 ms | 68,252 KiB |
| File verify | 0.86 ms | 3,156 KiB |
| Create manifest for 1,000 small files | 8.97 ms | 3,436 KiB |
| Create manifest for one 128 MiB file | 84.1 ms | 3,144 KiB |
| Manifest sign | 112.0 ms | 68,932 KiB |
| Verify 1,000-file manifest | 8.67 ms | 3,452 KiB |

The release binary measured 1,239,080 bytes. On the 128 MiB hash input, median SHA-256 times were 80 ms for `seal` and 90 ms for `sha256sum`; median BLAKE3 times were 30 ms for `seal` and 10 ms for `b3sum`. Values are rounded from the recorded five-run results. The full run metadata and raw hyperfine output are in the `seal-hash-benchmark` artifact from the manual Hash benchmark workflow; host load and filesystem caching can affect these results.
