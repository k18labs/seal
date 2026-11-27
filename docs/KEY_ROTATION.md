# Key rotation and recovery

Seal uses explicit public-key selection. A key fingerprint is the identity users should verify through a channel independent of the signed files and download host.

## Planned rotation

1. Generate the replacement key in a controlled environment and back up its encrypted private-key file securely.
2. Publish the new public-key fingerprint through the project's established independent channels before switching signers.
3. During the transition, distribute both fingerprints and state which releases each key signs. Verify each signature with the corresponding explicitly selected key.
4. After the transition, stop accepting the old fingerprint for new releases. Retain old public keys only to verify historical artifacts when policy permits.

## Suspected compromise

Stop using the affected private key. Publish a revocation notice and the replacement fingerprint through independent channels. Users must remove the old key from their own trust configuration; Seal has no built-in revocation service or trusted-key bundle. Treat artifacts signed after the suspected compromise time as untrusted unless independently reissued and verified with the replacement key.

Never infer trust from a public key stored beside an artifact. Keep encrypted backups and recovery access separate from routine signing credentials. A signature confirms the artifact matches what a key signed; it does not establish the key owner's identity without independent fingerprint verification.
