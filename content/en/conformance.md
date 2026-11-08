---
key: conformance
lang: en
path: /conformance/
nav: conformance
title: Conformance
description: Conformance classes of Sanad, the public test vectors and the reference verifier.
docid: SANAD-CONF-0.1
version: 0.1
toc: true
numbered: true
---

<!-- glance -->
- An implementation conforms if it produces the expected result on every public test vector.
- Anyone whose implementation passes may state that it conforms to Sanad v0.1; the statement is free.
- The reference implementation passes all vectors (computed when this page is built).
<!-- /glance -->

## Conformance classes

<div class="cards wide">
<div><h3>Verifier</h3><p>Runs the recognition function under a policy and returns the result with the ordered explanation. Tested by the recognition and inference vectors.</p></div>
<div><h3>Issuer</h3><p>Emits claims, evidence bundles and credentials. Tested for canonical form and for a bundle hash that recomputes.</p></div>
<div><h3>Attestor</h3><p>Signs blind marks. Tested for commit and reveal and for signature verification.</p></div>
<div><h3>Log</h3><p>Serves signed checkpoints and proofs. Tested for inclusion and consistency proofs.</p></div>
<div><h3>Indexer</h3><p>Lists opt-in skill cards. Tested for set results without ranking and for consent.</p></div>
</div>

## Run the reference verifier

The reference implementation (TypeScript, no dependencies) is in `reference/` of the project repository, together with a ready-built module. From a clone of the repository:

```
node reference/verify.mjs
```

The command prints PASS or FAIL for each vector with the rule identifiers of the explanation and exits with code 0 only if all vectors pass. `reference/README.md` explains how a second implementer reproduces the worked example of Appendix A of the specification.

## The test vectors

Each vector contains a policy, a credential and the expected status, level, attested level, confidence, dropped items and the rules that must appear in the explanation. The file is `reference/vectors.json`. The table shows the current result of the reference implementation.

<!-- vectors-table -->

## How to test an implementation

1. Obtain `vectors.json` for the version that is implemented.
2. Run the implementation on every vector.
3. Compare the full result, including the ordered rule identifiers of the explanation, with the expected result.
4. Publish the result together with the version of the vectors used.

## Versions

A change that alters the expected result of any vector is a new minor version. The text of a version is frozen once published.
