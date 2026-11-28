# Installing Seal

The intended binary distribution channel is GitHub Release archives. Package-manager support is deferred until user demand and update requirements are clear. The current `v1.0.0-rc.1` artifacts are release-candidate workflow artifacts, not a production GitHub Release; wait for a maintainer to publish a release before treating these instructions as a production download path.

Choose the archive matching the operating system and CPU architecture. The release workflow names archives `seal-<target>.tar.gz` for Linux and macOS, and `seal-<target>.zip` for Windows. Download the archive and its adjacent `.sha256` file from the same release.

Verify the checksum before extracting:

```sh
# Linux
sha256sum --check seal-x86_64-unknown-linux-gnu.tar.gz.sha256

# macOS
shasum -a 256 --check seal-aarch64-apple-darwin.tar.gz.sha256
```

On Windows PowerShell, compare the digest in the downloaded checksum file:

```powershell
$archive = "seal-x86_64-pc-windows-msvc.zip"
$expected = (Get-Content "$archive.sha256").Split()[0].ToLowerInvariant()
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 checksum mismatch" }
```

Then verify build provenance with GitHub CLI, checking both the repository and the release workflow identity:

```sh
gh attestation verify seal-x86_64-unknown-linux-gnu.tar.gz \
  --repo k18labs/seal \
  --signer-workflow k18labs/seal/.github/workflows/release.yml
```

Use the archive matching your target in that command. Extract it only after checksum and provenance verification. A checksum detects transfer damage when its expected value is trusted; provenance authenticates build context, not publisher intent or software safety. For signed files or directories, separately obtain the trusted public key fingerprint through an independent channel and follow [key management](KEY_MANAGEMENT.md).

## Clean-machine verification

Use a separate machine or a fresh environment with no Seal release key already installed. Obtain the expected release-key fingerprint from a channel independent of the downloaded archive and its release assets. Do not accept a public key and its expected fingerprint from the same download location.

If the publisher supplies a detached Seal signature for the archive, check the key fingerprint first:

```sh
seal key fingerprint --public-key ./seal-release-key.pub
```

Compare the complete `SHA256:` fingerprint with the value from the independent channel. Only after it matches, verify the archive signature:

```sh
seal verify ./seal-x86_64-unknown-linux-gnu.tar.gz \
  --signature ./seal-x86_64-unknown-linux-gnu.tar.gz.seal \
  --public-key ./seal-release-key.pub
```

Use the archive, signature, and public-key filenames for the selected target. A Seal signature proves that the matching key signed the file; trust in the publisher depends on independently checking that key's fingerprint. A checksum only detects a mismatch against the checksum value you chose to trust. GitHub provenance attestation ties an artifact to a repository and workflow identity; it does not establish publisher intent or that the software is safe. These checks answer different questions. The current release workflow documents checksums and GitHub provenance; do not assume a detached Seal signature is published unless the release actually includes one.
