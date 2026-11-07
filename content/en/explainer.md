---
key: explainer
lang: en
path: /explainer/
nav: explainer
title: Explainer: why this level?
description: An interactive page that shows a sample credential as a chain and lets you change the verifier policy.
---

<!-- glance -->
- A sample credential is drawn as a chain: skill, claim, evidence, attestations, attestors.
- You change the **verifier's policy** and the same evidence gives a different level, with the explanation recalculated.
- You can recompute the hashes in your browser and see a tampered mark being detected.
<!-- /glance -->

## Where it is

The explainer is a page of the Kamangir project, which wrote the reference code: <a href="https://kamangir.school/en/recognition/">kamangir.school/en/recognition/</a>. It is **hosted by the Kamangir project for now** and runs the same recognition function that the conformance vectors test, in your browser, with invented data. It may be unavailable until the host site has been updated. A copy under this domain is planned.

## What it shows

- **The chain:** each node shows its hash and the rule that used it.
- **Verifier policy:** minimum number of attestors, whether a live sitting is required, the half-life of evidence, the trust threshold for attestors. Moving a control recomputes the level, the confidence and the explanation.
- **Hidden skills:** prerequisite skills that follow from a demonstrated skill, each marked as **inferred**, with the path that produced it. The holder decides whether to publish them.
- **What it does not prove:** a short, honest box on the limits of any such chain.
