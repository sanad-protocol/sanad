# Sanad core (package `@sanad-protocol/core` 0.2.0, algorithm `sanad-0.1`)

A small TypeScript implementation of the Sanad recognition function with no runtime dependencies, together with the conformance vectors. It is the reference for **Verifier**, **Issuer** and a part of **Log** conformance in the specification (`SANAD-SPEC-0.1`). The Sanad engine (`engine/`) builds on it.

Package version 0.2.0 implements algorithm `sanad-0.1` with the differences from the v0.1 reference listed below; the 20 vectors give the same results as in 0.1. The rules of this code differ from the v0.1 reference (the code published with the specification) in these ways: (1) a second mark by the same attestor on one evidence item is dropped under R1, where v0.1 counted both; (2) with the optional signature check, a failing signature drops the attestation under R1, where v0.1 did not check signatures; (3) a policy must be complete and in range and `claimedLevel` must be 0 to 5, otherwise the function refuses with a `RangeError`, where v0.1 computed a result from whatever it was given (a missing field acted as zero or undefined); (4) the attestor name `replay` is reserved, statistics are read from own numeric properties only, and an optional verifier allow-list exists. On credentials without duplicate marks, with a complete valid policy and without a signature check, the results equal v0.1's, and the 20 conformance vectors give the same results; on random credentials that contain duplicate marks the results differ (an independent review measured 2,500 of 20,000). The algorithm string stays `sanad-0.1`; whether the changed rules deserve a new algorithm id is open (`docs/SPEC-DECISIONS-NEEDED.md`, decision 11). New in 0.2.0: an optional signature check in R1 (`recognise(credential, policy, { verifySignature })`; without it signatures are not checked, as in v0.1), exported sealing helpers (`commitOf`, `attestationHashOf`, `sealEvidence`, `sealAttestations`, ...), type declarations (`dist/sanad-reference.d.ts`), an `exports` map and the command `sanad`.

| File | Purpose |
|---|---|
| `src/types.ts` | Data model: evidence, attestations, credential, policy, result |
| `src/canon.ts`, `src/sha256.ts` | Canonical JSON and SHA-256 (pure code, checked against two other implementations) |
| `src/seal.ts`, `src/tamper.ts` | Building a sealed credential; applying a change to test integrity checks |
| `src/recognise.ts` | Rules R1 to R7 (integrity, admissibility, age, per-evidence level, independence, level, confidence) |
| `src/infer.ts` | Rule R8 (hidden skills, inferred, with derivation paths) |
| `src/sample.ts` | The worked example of Appendix A of the specification |
| `vectors.json` | 15 recognition vectors and 5 inference vectors with expected results |
| `verify.mjs`, `run.mjs` | Command-line verifier (`verify.mjs`) and the function that runs every vector (`run.mjs`) |
| `dist/sanad-reference.mjs`, `dist/sanad-reference.d.ts` | One dependency-free ES module built by `build.mjs` (committed), and its type declarations (kept in `types/`) |
| `bin/sanad.mjs` | Command `sanad`: `run-vectors [file]`, `verify <credential.json> [--policy <file>]` (recognition only; signatures are checked by `sanad-engine verify`) |

## Run the vectors

```
node reference/verify.mjs                 # the bundled vectors
node reference/verify.mjs my-vectors.json # your own file in the same format
```

The exit code is 0 only if every vector passes. To rebuild the bundle: `npm ci && node reference/build.mjs`. To run the unit tests: `npx vitest run`.

## Reproduce Appendix A independently

Appendix A of the specification states a claim at level 4 with a practice run, a live sitting attested by three examiners (levels 4, 4, 3) and a peer review, and a strict policy. A second implementer reproduces it in four steps:

1. Read `src/sample.ts` for the data of the credential and `src/types.ts` for the policy fields.
2. Implement the rules R1 to R8 of section 5 of the specification in your language; the explanation text is not compared, the rule identifiers are.
3. Run your implementation on the 15 recognition vectors and the 5 inference vectors in `vectors.json`. Each vector gives the policy, the credential, and the expected status, level, attested level, confidence (3 decimals), dropped items and rules that must appear in the explanation.
4. Compare your output with the output of `node reference/verify.mjs`. Where they differ, the vectors win over the text and the difference is a defect to report (see `CONTRIBUTING.md`).

## Notes

- The signature field in the 20 vectors is a placeholder string; real Ed25519 signatures are produced and checked by the engine (`engine/`, vectors `engine/vectors/engine-*.json`).
- Licence: Apache-2.0 (code) and CC BY 4.0 (the vectors and this text).
