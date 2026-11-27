# CLI reference

## `seal hash PATH`

Hashes one regular file. `--algorithm sha256|blake3` selects the digest, defaulting to SHA-256. `--json` prints one JSON object with `algorithm`, `digest`, and `path` fields. In human mode the output is the lowercase digest, two spaces, and a path with terminal control characters escaped.

## `seal version`

Prints the package version. Use `seal --help` for parser-generated usage.

## Key and signature commands

```text
seal keygen --out PRIVATE_PATH
seal key fingerprint --public-key PUBLIC_PATH
seal key inspect --public-key PUBLIC_PATH
seal sign FILE --key PRIVATE_PATH --output SIGNATURE_PATH
seal verify FILE --signature SIGNATURE_PATH --public-key PUBLIC_PATH [--json]
```

Key generation creates `PRIVATE_PATH` and `PRIVATE_PATH.pub`, and fails rather than overwriting either. File signatures use the format in [SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md). The public key must come from a separately trusted source.

Current exit statuses: 0 success/help/version; 1 content integrity mismatch; 2 invalid signature; 3 invalid or untrusted public key; 4 malformed input; 5 I/O or output failure; 6 invalid command-line usage; 7 unsupported algorithm or format. JSON verification writes one result object to stdout, sends diagnostics to stderr, and returns the same nonzero status on failure.
