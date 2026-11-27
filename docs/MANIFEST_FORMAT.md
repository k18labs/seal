# Seal manifest format, version 1

## Canonical representation

A manifest is UTF-8 JSON with no byte-order mark and exactly one final LF. It is compact (no whitespace), uses the field order and JSON escaping emitted by `serde_json` for the structs below, and has no unknown or duplicate fields. Parsers MUST reserialize the parsed data and require byte-for-byte equality with the input. This makes the exact signed bytes canonical.

Top-level fields are `version` (integer `1`), `algorithm` (string `sha256`), and `files` (array). Each file record has fields `path` (string), `size` (unsigned 64-bit integer), and `digest` (64 lowercase hexadecimal characters). Example empty manifest:

```json
{"version":1,"algorithm":"sha256","files":[]}
```

Records are sorted by ascending UTF-8 byte sequence of `path`, with strictly increasing paths. Paths are relative slash-separated portable ASCII components using only letters, digits, `.`, `_`, and `-`; `/` is the separator. Empty components, leading `/`, `.` and `..`, trailing dots, Windows reserved device names, non-ASCII bytes, and case-insensitive ASCII collisions are rejected. Paths are limited to 1,024 bytes and 64 components. The path policy intentionally excludes names that cannot be represented consistently across supported platforms.

## Limits and interpretation

The encoded manifest is at most 16 MiB, contains at most 100,000 records, and the sum of declared file sizes is at most 1 TiB. A tree scan also visits at most 200,000 total file and directory entries. Version 1 permits only SHA-256 and carries no timestamps or ownership/mode metadata. Empty directories are not represented. Hard links are recorded as independent paths with the digest and size of the bytes read; inode identity is not represented.

Creation and verification reject symbolic links, Windows reparse points, and non-regular objects. Traversal uses capability-scoped directory handles and no-follow opens. The implementation checks file size and modification time before and after reading and directory modification time around traversal. Filesystems do not provide an atomic snapshot here: concurrent changes can still race between checks. A successful result means that the bytes read matched the manifest during this operation, not that the tree remains unchanged afterward.

## Signing

The manifest signature uses the common outer record defined in [SIGNATURE_FORMAT.md](SIGNATURE_FORMAT.md), with `object manifest`, SSHSIG namespace `seal-manifest-v1`, and the 64-byte signed message `SEAL-MANIFEST-V1\0sha256\0 || uint64_be(manifest_byte_length) || SHA256(manifest_bytes)`. The signature binds the exact canonical bytes. Verification validates canonical form, signature algorithm/namespace and explicit public-key match, then checks the exact tree file set and contents.

The maintainer reports that qualified external format review found no blocking findings; the report is not included in this repository. Interoperability implementations should still be tested against published vectors before relying on them.
