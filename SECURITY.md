# Security policy

## Scope and current limits

Seal is an offline file and directory integrity tool. It supports SHA-256 and optional BLAKE3 hashing, Ed25519 file and manifest signatures, explicitly selected trusted public keys, and encrypted private-key files.

No independent security audit or format review has been completed. Manifest verification is not an atomic filesystem snapshot; files can change between metadata checks, and results describe only the bytes observed during that run. Seal does not establish software safety, freshness, or publisher trust unless the selected key was obtained through an authenticated channel. The format and implementation limitations are described in [the threat model](docs/THREAT_MODEL.md) and [the roadmap](ROADMAP.md).

Do not use Seal as antivirus software or as an automatic installer. Do not treat a public key or checksum distributed only beside an artifact as trusted.

## Reporting

Report suspected vulnerabilities through the repository's GitHub Security Advisories interface when available. Avoid posting exploit details publicly before maintainers have had a reasonable chance to respond.
