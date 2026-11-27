# CI integration

The examples under `examples/github-actions` use a pinned Seal source revision. Review and update the pin deliberately. Never download the trusted public key from the same artifact or release being verified: store it in a protected CI secret or provision it through another trusted channel, and check its expected fingerprint during setup.

- `hash.yml` shows SHA-256 JSON output for an artifact.
- `verify-manifest.yml` demonstrates trusted-key manifest verification and fails the job on any nonzero Seal exit status.

Seal's GitHub artifact provenance is separate from its Ed25519 signature. The signed-manifest example also runs `gh attestation verify` with both the expected repository and release workflow identity before checking the directory signature. Replace those identity values when adapting it to another producer. Provenance does not establish publisher intent or software safety. GitHub release archives are the initial binary installation channel; package-manager support remains deferred until user demand is known.
