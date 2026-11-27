# Key management

`seal keygen --out PATH` generates an Ed25519 key using the operating-system randomness provider exposed through `ssh-key`'s `getrandom` feature. It writes an unencrypted OpenSSH private key to `PATH` and a public key to `PATH.pub`, and fails if either file already exists. On Unix, the private key is created with mode `0600`. On Windows, Rust creates the file with the inherited ACL of the selected directory; Seal does not currently replace or audit that ACL, so choose and verify a private directory. Do not treat this Windows behavior as a full ACL guarantee.

The private key is plaintext OpenSSH key data. Seal does not accept passphrases, encrypt keys, or promise that every in-memory copy is erased. Store the key in a user-controlled private directory and keep backups protected. The CLI prints only key paths and the public fingerprint, never private-key contents.

Public keys use the OpenSSH `ssh-ed25519` representation. Fingerprints use OpenSSH SHA-256 fingerprint formatting. Verification always requires an explicit `--public-key`; a key carried in the signature record is only an identity hint and must match the supplied key exactly. Obtain the expected fingerprint through an independently authenticated channel.
