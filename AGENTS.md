# Seal repository guidance

- Preserve the single-crate layout unless a concrete need justifies a change.
- Keep cryptography in established libraries; never implement cryptographic primitives.
- Keep file processing streamed and bounded in memory.
- Do not claim signing, key trust, or directory verification until the behavior exists and is tested.
- Keep formats strict, versioned, documented, and reject unknown identifiers.
- Do not print secrets or treat an artifact-supplied public key as trusted.
- Run formatting, locked tests, and clippy before reporting code changes.
- Document actual verification results and limitations.
