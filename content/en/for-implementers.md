---
key: for-implementers
lang: en
path: /for/implementers/
nav: for
title: For implementers
description: How to build a Sanad verifier, issuer, attestor, log or index, and how to test it.
crumbs: [["Who it is for","/for/"]]
---

<!-- glance -->
- A reference implementation (TypeScript, no dependencies) and 20 test vectors are published.
- A second and a third independent implementation are the most valuable contributions now.
<!-- /glance -->

Pick a conformance class: Verifier, Issuer, Attestor, Log or Indexer. The most useful first step is a Verifier in another language.

1. Read sections 3 to 5 of the [specification](/spec/0.1/).
2. Run `node reference/verify.mjs` to see 15 recognition vectors and 5 inference vectors pass.
3. Implement rules R1 to R8; compare your output with the vectors, including the rule identifiers.
4. Publish your results and tell the project: info@sanadprotocol.org or an issue in the repository once it is public.

Code is Apache-2.0 (with a patent grant); the specification text is CC BY 4.0. The steward has committed to a [royalty-free patent licence](/ipr/) for implementing the specification.

**Next step:** open [Conformance](/conformance/) and the `reference/README.md` instructions.
