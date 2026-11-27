# Seal file signature format, version 1

## Structure

The signature file is UTF-8 text with LF line endings and a final LF. It consists of five fixed metadata lines followed by one OpenSSH SSHSIG PEM object:

```text
SEAL-SIGNATURE 1
object file
hash sha256
size <canonical-u64-decimal>
digest <64-lowercase-hex-characters>
-----BEGIN SSH SIGNATURE-----
<base64 SSHSIG body>
-----END SSH SIGNATURE-----
```

There are no additional fields, blank lines, or trailing bytes. The parser rejects unknown version, object, hash, noncanonical size (no leading zero except `0`), uppercase/non-hex digest characters, invalid PEM, and inputs larger than 65,536 bytes. The inner SSHSIG parser rejects unknown versions and Seal requires Ed25519, SSHSIG hash algorithm `sha256`, and namespace `seal-file-v1`.

For manifests, the second line is `object manifest`, the namespace is `seal-manifest-v1`, and the signed message is the 64-byte envelope `SEAL-MANIFEST-V1\0sha256\0 || uint64_be(manifest_length) || SHA256(canonical_manifest_bytes)`. The outer record shape and limits are otherwise identical. See [MANIFEST_FORMAT.md](MANIFEST_FORMAT.md).

## Signed message

The signed message is exactly the concatenation of:

1. ASCII bytes `SEAL-FILE-V1`, then NUL, then ASCII `sha256`, then NUL.
2. The file size as an unsigned 64-bit big-endian integer.
3. The 32 raw bytes represented by the `digest` field.

`digest` is SHA-256 over the complete file byte stream. `size` is the number of bytes read from that same stream. The OpenSSH SSHSIG layer hashes this fixed message using SHA-256, prefixes its standard SSHSIG signed-data structure, and signs it with Ed25519. Signatures are deterministic for identical key and file bytes.

The signature's SSH public key identifies the signer but does not establish trust. `seal verify` requires a separate OpenSSH public key and requires exact key-data equality before returning success.

## Verification order and outcomes

1. Parse and strictly validate the outer record and SSHSIG metadata.
2. Recreate the fixed message from the signed size and digest.
3. Verify the SSHSIG using its embedded key; reject a bad signature.
4. Compare that key with the explicitly supplied public key; reject a mismatch as untrusted.
5. Stream the artifact, compute SHA-256 and byte count, and compare both with the signed values.

Exit status 0 means all checks passed. Status 2 means cryptographic signature failure, 3 means the key is untrusted or invalid, 4 means malformed input, 5 means an operational error, and 1 means the signed metadata is valid but the artifact's bytes or size differ.

## Interoperability

The inner signature is OpenSSH SSHSIG and can be independently decoded with SSHSIG-compatible implementations. The outer Seal record and the Seal message envelope are format-specific. To verify with an independent SSHSIG implementation, reconstruct the exact 60-byte message described above and use namespace `seal-file-v1`. This is not directly equivalent to running `ssh-keygen -Y verify` over the original artifact. The maintainer reports that qualified external format review found no blocking findings; the report is not included in this repository.
