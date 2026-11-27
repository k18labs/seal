# Release checklist

Use this checklist before publishing a production release.

- [ ] Confirm the release version in `Cargo.toml`, `Cargo.lock`, and the annotated tag.
- [ ] Review the exact source commit and changelog; ensure the working tree is clean.
- [ ] Run formatting, locked tests, and clippy; require all supported CI targets to pass.
- [ ] Build the supported archives and SBOM from the tagged commit.
- [ ] Verify archive checksums and GitHub artifact attestations from a separate checkout.
- [ ] Publish the signer public-key fingerprint through an independent channel. Do not treat a key bundled beside the archive as trusted.
- [ ] Verify installation and signature examples from a clean machine and document all commands.
- [ ] Review known limitations, especially the lack of an atomic filesystem snapshot and the absence of a full independent implementation audit.
- [ ] Confirm release notes describe supported targets and the exact verification procedure.
- [ ] After publishing, verify the release page, archive links, checksums, and provenance again.

Production release publication and the `v1.0.0` tag remain a maintainer decision.
