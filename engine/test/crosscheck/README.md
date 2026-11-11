# Cross-check: a second, independent verifier

`xcheck.py` verifies a Sanad engine credential without using any engine code. It was written from `spec/SPEC-v0.1.md` and `engine/DESIGN.md` alone and uses only the Python 3 standard library. It contains its own Ed25519 verification (RFC 8032, strict: the scalar must be below the group order), canonical JSON (RFC 8785 number formatting and UTF-16 key order), SHA-256 handling, the RFC 9162 inclusion check and the recognition function of section 5 of the specification.

It checks: the issuer proof, every evidence hash, the kind and date mirrored into the hashed body, every commit binding, every attestation hash and chain link, every attestor signature (did:key only), the bundle hash, the log checkpoint signature, every inclusion proof, that each attestation hash and the bundle hash are log leaves, and that each commit leaf can be reconstructed from the credential data. It then computes recognition under a fixed policy.

```
python3 engine/test/crosscheck/xcheck.py credential.json - 2026-03-03
```

The third argument is the evaluation day. Every line starts with `PASS` or `FAIL`; the last line reports the number of failures.

What it shows, and does not show:

- It is a second implementation of the verifier. Agreement means that the engine's documented formats are enough for an independent reader to reproduce its hashes and signatures; a disagreement is a defect in the engine or in its documentation.
- It is not a cryptographic review. It shares no code with the engine but was written against the same documents.
- Its month length (365.2425 / 12 days) differs from the core's (30.4375 days; see `DESIGN.md` section 14, item 4), so confidence values can differ in the third decimal; the test compares status and level only.
- It resolves did:key identities only.

`engine/test/crosscheck.test.mjs` runs it on credentials made by the example runs whenever `python3` is available.
