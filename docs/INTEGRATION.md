# Integration

`seal hash PATH --json` emits a digest record. `seal verify PATH --signature SIG --public-key PUB --json` emits a verification result with signature, signer-trust, and integrity status fields. It returns nonzero for every incomplete or failed verification. Keep diagnostics on stderr and use the explicitly trusted public key distributed over a separate authenticated channel.

There is not yet a directory manifest or complete release verification workflow. CI examples for release directories will be added after manifest verification is implemented.
