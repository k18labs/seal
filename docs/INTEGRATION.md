# CI integration

The examples under `examples/github-actions` use a pinned Seal source revision. Review and update the pin deliberately. Never download the trusted public key from the same artifact or release being verified: store it in a protected CI secret or provision it through another trusted channel, and check its expected fingerprint during setup.

- `hash.yml` shows SHA-256 JSON output for an artifact.
- `verify-manifest.yml` demonstrates trusted-key manifest verification and fails the job on any nonzero Seal exit status.

Seal's GitHub artifact provenance is separate from its Ed25519 signature. Verify provenance against the expected repository and workflow identity with GitHub's `gh attestation verify` before trusting build origin. Provenance does not establish publisher intent or software safety. GitHub release archives are the initial binary installation channel; package-manager support remains deferred until user demand is known.
