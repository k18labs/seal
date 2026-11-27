# CLI reference

## `seal hash PATH`

Hashes one regular file, or standard input when `PATH` is `-`. `--algorithm sha256|blake3` selects the digest, defaulting to SHA-256. `--json` prints one JSON object with `schema_version` (currently `1`), `algorithm`, `digest`, and `path` fields. In human mode the output is the lowercase digest, two spaces, and a path with terminal control characters escaped.

## `seal version`

Prints the package version. Use `seal --help` for parser-generated usage.

## Key and signature commands

```text
seal keygen --out PRIVATE_PATH [--passphrase-file FILE]
seal key fingerprint --public-key PUBLIC_PATH
seal key inspect --public-key PUBLIC_PATH
seal sign FILE --key PRIVATE_PATH --output SIGNATURE_PATH [--passphrase-file FILE]
seal verify FILE --signature SIGNATURE_PATH --public-key PUBLIC_PATH [--json]
```

Without `--passphrase-file`, key generation prompts twice and signing prompts once. The file option accepts one UTF-8 line and should be used only with a controlled automation secret. See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) for format and storage details.

Directory commands are `seal manifest create ROOT --output FILE [--json]`, `seal manifest sign FILE --key PRIVATE_PATH --output SIGNATURE_PATH [--passphrase-file FILE]`, and `seal manifest verify FILE --root ROOT --signature SIGNATURE_PATH --public-key PUBLIC_PATH [--json]`. Verification requires an exact file set and fails on symlinks, reparse points, special objects, unsafe or unrepresentable paths, or files that change while read.

`seal completions bash|zsh|fish|powershell` writes a completion script generated from the current command tree. `manifest create` and `manifest verify` accept `--progress`; progress goes to stderr and JSON remains on stdout. `manifest inspect FILE [--json]` displays a canonical manifest without reading tree files. `manifest compare LEFT RIGHT [--json]` reports added, removed, and changed entries and does not verify files on disk.

JSON-capable commands are `hash`, `verify`, `manifest create`, `manifest inspect`, `manifest compare`, and `manifest verify`. Each JSON object includes `schema_version: 1`. Verification results include `verified`, structured error details, and an exit status that remains nonzero on failure; `manifest compare` includes `verifies_files_on_disk: false`. Other commands currently emit human-readable output only.

Key generation creates `PRIVATE_PATH` and `PRIVATE_PATH.pub`, and fails rather than overwriting either. File signatures use the format in [SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md). The public key must come from a separately trusted source.

Current exit statuses: 0 success/help/version; 1 content integrity mismatch; 2 invalid signature; 3 invalid or untrusted public key; 4 malformed input; 5 I/O or output failure; 6 invalid command-line usage; 7 unsupported algorithm or format. JSON verification writes one result object to stdout, sends diagnostics to stderr, and returns the same nonzero status on failure.
