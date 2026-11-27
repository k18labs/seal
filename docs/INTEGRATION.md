# Integration

## CI hash verification

```sh
seal hash dist/relay-linux-x86_64.tar.gz --json
```

An unsigned digest is useful only when its expected value comes through an authenticated channel.

## Signed release directory

```sh
seal manifest create ./dist --output release.manifest
seal manifest sign release.manifest --key ./keys/release --output release.manifest.seal
```

Distribute `release.manifest`, `release.manifest.seal`, the files, and the trusted release public key via separately authenticated channels. The user must obtain the expected public-key fingerprint independently; including a public key beside the artifact does not establish trust.

```sh
seal manifest verify release.manifest --root ./dist \
  --signature release.manifest.seal \
  --public-key ./trusted/release.pub --json
```

Exit status zero means the signature matched the explicitly supplied key and the directory file set and contents matched. Any missing, unexpected, or modified file fails verification. Seal does not execute verified files or decide whether they are safe.

GitHub Actions release-candidate artifacts include SHA-256 checksums and provenance attestations. Verify an artifact's GitHub provenance with `gh attestation verify ARTIFACT --repo k18labs/seal`; verify the source ref and workflow identity in the result. Provenance authenticates the build context, not the software's safety. Bootstrap trust must not rely exclusively on Seal itself.