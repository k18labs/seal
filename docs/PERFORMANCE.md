# Performance

Hash input is processed with a fixed 65,536-byte buffer. The scan remains serial; the measurements below establish a baseline and do not compare serial hashing with a parallel implementation.

## Cross-platform baseline

Measured by the manual [Operation benchmark workflow](https://github.com/k18labs/seal/actions/runs/46062784386), using source revision `f8a2e481b4041a0e09ed32e97ff79eccdd898beb`, Rust 1.96.0, and the release profile in `Cargo.toml`. The Linux x64, macOS ARM64, and Windows x64 GitHub-hosted jobs each used a 128 MiB deterministic input, a tree of 1,000 small files, one warmup, and five timed runs. Times include process startup and use warm caches. Each cell shows median time / largest sampled child RSS across timed runs.

| Operation | Linux x64 | macOS ARM64 | Windows x64 |
| --- | ---: | ---: | ---: |
| `seal version` | 10.09 ms / 236 KiB | 29.13 ms / 656 KiB | 10.14 ms / 1,756 KiB |
| File sign | 112.05 ms / 68,752 KiB | 144.72 ms / 67,664 KiB | 112.71 ms / 70,504 KiB |
| File verify | 10.10 ms / 212 KiB | 19.71 ms / 672 KiB | 10.17 ms / 4,212 KiB |
| Create manifest for 1,000 small files | 10.09 ms / 236 KiB | 18.36 ms / 656 KiB | 51.53 ms / 5,244 KiB |
| Create manifest for one 128 MiB file | 91.45 ms / 3,400 KiB | 471.78 ms / 2,000 KiB | 123.79 ms / 5,388 KiB |
| Manifest sign | 111.96 ms / 69,112 KiB | 116.98 ms / 67,952 KiB | 113.47 ms / 70,688 KiB |
| Verify 1,000-file manifest | 10.09 ms / 204 KiB | 49.83 ms / 672 KiB | 51.46 ms / 5,580 KiB |

| Target | Release binary size |
| --- | ---: |
| `x86_64-unknown-linux-gnu` | 1,404,024 bytes |
| `aarch64-apple-darwin` | 1,015,488 bytes |
| `x86_64-pc-windows-msvc` | 1,195,520 bytes |

Full run metadata, including min/max times, commands, target, build profile, toolchain, and source revision, is in the workflow artifacts. Peak RSS is sampled every 10 ms and can miss brief peaks, especially for short commands. These are single-runner observations, not performance guarantees or cross-machine comparisons. The manifest scan result for the 128 MiB file uses only a few MiB of sampled RSS on these runners, consistent with streamed processing; the sampler can understate short-lived memory use.

The measurements do not show whether parallel hashing would improve performance. Keep the current serial implementation until a comparative benchmark demonstrates a clear benefit and a bounded memory design.

## Reproducibility evidence

The Windows x64 release executable measured 1,028,096 bytes in a separate Rust 1.96.0 reproducibility check. Two clean builds on one Windows ARM64 host using x64 tools produced the same SHA-256, `0c8ac5cb0bad03339fe08e26995e136622104aa0b9153ce9d57923be07b2fb4c`. Evidence is in `docs/evidence/reproducibility-windows-x64-local.json`. This covers one target on one host and does not establish cross-host reproducibility.
