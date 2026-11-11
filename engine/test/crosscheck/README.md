# Cross-check: a second, independent verifier

`xcheck.py` verifies a Sanad engine credential without using any engine code. It was written from `spec/SPEC-v0.1.md` and `engine/DESIGN.md` alone and uses only the Python 3 standard library. It contains its own Ed25519 verification (RFC 8032, strict: the scalar must be below the group order), canonical JSON (RFC 8785 number formatting and UTF-16 key order), SHA-256 handling, the RFC 9162 inclusion check and the recognition function of section 5 of the specification.

It checks: the issuer proof, every evidence hash, the kind and date mirrored into the hashed body, every commit binding, every attestation hash and chain link, every attestor signature (did:key only), the bundle hash, the log checkpoint signature, every inclusion proof, that each attestation hash and the bundle hash are log leaves, and that each commit leaf can be reconstructed from the credential data. It then computes recognition under a fixed policy.

```
python3 engine/test/crosscheck/xcheck.py credential.json --as-of 2026-03-03 --half-life 36 --issuer <did> --log-key <did>
python3 engine/test/crosscheck/xcheck.py credential.json --as-of 2026-03-03 --allow-unpinned     # internal consistency only
```

Every line starts with `PASS` or `FAIL`; the last line reports the number of failures and the exit code is 1 if any check failed. **Pins:** without `--issuer` and `--log-key` the verifier prints `FAIL pins` and exits 1, because a credential made by any stranger's engine is internally consistent; `--allow-unpinned` accepts that knowingly and says so. A malformed credential ends in a `FAIL` line, never a traceback. The embedded log entries are a subset of the log (a second assessment on the same log has a checkpoint larger than its entries); each is checked by its own inclusion proof.

What it shows, and does not show:

- It is a second implementation of the verifier. Agreement means that the engine's documented formats are enough for an independent reader to reproduce its hashes and signatures; a disagreement is a defect in the engine or in its documentation.
- It is not a cryptographic review. It shares no code with the engine but was written against the same documents.
- Its month length (365.2425 / 12 days) differs from the core's (30.4375 days; see `DESIGN.md` section 14, item 4), so confidence values can differ in the third decimal; the test compares status and level only.
- It resolves did:key identities only.

`engine/test/crosscheck.test.mjs` runs it on credentials made by the example runs whenever `python3` is available.

## The Ruby verifier

`sanad_verify.rb` is a second independent verifier, written in Ruby (standard library only) from the same documents. It has its own Ed25519, canonical JSON, RFC 9162 check and recognition function, and additionally checks that commit leaves can be reconstructed from the credential and that every commit leaf precedes the first attestation leaf.

```
ruby engine/test/crosscheck/sanad_verify.rb credential.json 2026-03-03 36 --issuer <did> --log-key <did>   # evaluation day and half-life in months (also --as-of, --half-life)
ruby engine/test/crosscheck/sanad_verify.rb credential.json 2026-03-03 36 --allow-unpinned
ruby engine/test/crosscheck/sanad_verify.rb --selftest
```

Without pins it prints `FAIL pins` and `OVERALL: FAIL` (exit 1) unless `--allow-unpinned` is given. The evaluation day and half-life default to 2026-03-12 and 24 months when not given; an earlier version ignored the positional arguments and so gave confidence 0.933 where the engine gave 0.936 for the same example credential at 2026-03-03 and 36 months: the cause was the verifier's own defaults (a later evaluation day and a shorter half-life), not rounding, ordering or the month length. A test pins both numbers. It uses the core's month length (30.4375 days); set `MONTH=30.436875` to see the specification text's value. It resolves `did:key` identities, and a `did:web` key only if given `PINNED_DIDWEB_KEY`. `engine/test/crosscheck.test.mjs` runs it when `ruby` is available. Like the Python verifier it is not a cryptographic review.

