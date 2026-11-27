# Security policy

## Current guarantees and limits

Seal 0.1.0 hashes regular files using established SHA-256 or BLAKE3 implementations and streams input through a fixed-size buffer. A digest is useful for integrity comparison only when the expected digest is obtained through a trusted channel. Hashing does not authenticate a publisher or establish that software is safe.

Seal currently has no signature verification or trusted-key model, no directory verification, no protection against concurrent file replacement, and no independent security audit. Do not use this version as a release-authentication system.

## Reporting

Until an authenticated private reporting channel is established, report suspected defects through the repository's GitHub Security Advisories interface when available. Do not post exploit details publicly before maintainers have had a reasonable chance to respond.
