---
key: conformance
lang: en
path: /conformance/
nav: conformance
title: Conformance
description: Conformance classes of Sanad and how an implementation is tested against public vectors.
docid: SANAD-CONF-0.1
version: 0.1 (draft)
toc: true
numbered: true
---

<!-- glance -->
- An implementation **conforms** if it produces the expected result on every public test vector.
- Anyone who passes may say "conforms to Sanad v0.1". The statement is free and cannot be sold.
- The vectors are published in the repository as `reference/vectors.json`: 15 recognition vectors and 5 inference vectors.
<!-- /glance -->

## Conformance classes

| Class | What it does | What is tested |
|---|---|---|
| **Verifier** | Runs the recognition function with a policy and prints the explanation. | Result, status, confidence and the ordered rule identifiers on every vector. |
| **Issuer** | Emits claims, evidence bundles and credentials. | Canonical form and hashes; the bundle hash recomputes. |
| **Attestor** | Signs blind marks. | Commit and reveal; signature verification. |
| **Log** | Serves checkpoints and proofs. | Inclusion and consistency proofs. |
| **Indexer** | Lists opt-in skill cards. | Returns sets, never rankings; honours consent. |

## The test vectors

Each vector contains a policy, a claim, evidence, attestations and the expected result. The cases include: no evidence; practice only; one examiner where two are needed; two agreeing examiners; disagreeing examiners; a declared conflict of interest; stale evidence; a tampered hash; inference to prerequisite skills; and a strict and a loose policy over the same evidence.

## Run the reference verifier

The reference implementation (TypeScript, no dependencies) is in `reference/` of the project repository, with a ready-built module. Clone the repository and run:

```
node reference/verify.mjs
```

It prints PASS or FAIL for each of the 20 vectors with the rule identifiers of the explanation, and exits with code 0 only if all pass. `reference/README.md` explains how a second implementer reproduces the worked example of Appendix A. The vectors are also in this site's source at `reference/vectors.json`.

## How to test your implementation

1. Obtain `vectors.json` for the version you implement.
2. Run your implementation on every vector.
3. Compare the full result, including the ordered `explanation` rule identifiers, with the expected result.
4. Publish your result and the version of the vectors you used.

## Versions

A change that alters the expected result of any vector is a new minor version. The text of a version is frozen once published.
