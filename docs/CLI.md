# CLI reference

## `seal hash PATH`

Hashes one regular file. `--algorithm sha256|blake3` selects the digest, defaulting to SHA-256. `--json` prints one JSON object with `algorithm`, `digest`, and `path` fields. In human mode the output is the lowercase digest, two spaces, and a path with terminal control characters escaped.

## `seal version`

Prints the package version. Use `seal --help` for parser-generated usage.

Current exit statuses: 0 success/help/version; 5 I/O, unsupported file type, or output serialization failure; 6 invalid command-line usage; 7 unsupported algorithm or unavailable optional algorithm support. Stable codes for signature, trust, and manifest errors are not applicable because those commands do not exist yet.
