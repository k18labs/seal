# Future manifest and trust proposals

## Decision: preserve version 1 semantics

Version 1 manifests remain canonical, exact-tree inventories of regular file paths, sizes, and SHA-256 digests. They carry no timestamps, ownership, permissions, exclusions, or snapshot claims. Verification continues to compare the complete file set and reject unsupported filesystem objects. Supporting metadata, exclusions, or snapshot semantics would change what a signed manifest asserts, so each proposal needs a separate versioned-format specification, compatibility review, and tests before implementation.

## Decision: no built-in trust bundle for now

Seal keeps public-key selection explicit through `--public-key`. A built-in bundle would require documented key identity, update, rotation, revocation, offline storage, and compromise recovery behavior. No usage evidence in this repository justifies that policy surface yet. Users distribute and verify fingerprints independently; see `docs/KEY_ROTATION.md`. Revisit the proposal when concrete user workflows demonstrate demand.

## Decision: defer bounded parallel hashing pending measurements

The implementation remains serial until the cross-platform benchmark matrix records comparable throughput and peak memory. Any future parallel mode must bound queued work and buffers, preserve deterministic manifest bytes, and show a meaningful benefit on supported targets. No concurrency or memory-ceiling claim is made before those measurements exist.
