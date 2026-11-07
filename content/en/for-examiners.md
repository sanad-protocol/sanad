---
key: for-examiners
lang: en
path: /for/examiners/
nav: for
title: For examiners and assessors
description: What an attestor does in Sanad, how marks stay independent and how conflicts of interest are handled.
crumbs: [["Who it is for","/for/"]]
---

<!-- glance -->
- An attestor publishes a key and signs; verifiers decide whom to trust.
- Attestors are not vetted by the project. Independence rests on declared conflicts of interest, blind marking and the verifier's policy; the protocol does not enforce it.
<!-- /glance -->

## Attestation

An attestation is a signed statement about one item of evidence: the level awarded, the role of the attestor and a declaration of conflicts of interest.

## Blind marking

Each attestor first publishes a commitment to a mark and reveals it only after all commitments have been published.

## Conflicts of interest

Relationships that could bias a mark (family, employer, paid tutoring, same cohort) must be declared. An undeclared conflict that is discovered is recorded as a signed dispute.

## Record

The number of sittings and the agreement with other attestors on the same sittings are public and recomputable from the log. A verifier may set minimum values for both and may restrict itself to a named list of attestors.

**Next step:** read section 9 of the [specification](/spec/0.1/) and the attestor class on the [conformance page](/conformance/).
