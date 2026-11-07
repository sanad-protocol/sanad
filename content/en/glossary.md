---
key: glossary
lang: en
path: /glossary/
nav: glossary
title: Glossary
description: Terms used by the Sanad specification.
---

<dl class="defs">
<dt id="attestation">Attestation</dt><dd>A signed statement by an attestor about one evidence item: the level awarded, the role, a conflict-of-interest declaration, a blind-marking commitment and its reveal.</dd>
<dt id="attestor">Attestor</dt><dd>A person or organisation, identified by a decentralised identifier, who signs attestations. Nobody appoints attestors for the protocol; verifiers choose which to accept.</dd>
<dt id="claim">Claim</dt><dd>A statement that a subject has a skill at a level on a date.</dd>
<dt id="commit-reveal">Commit and reveal</dt><dd>A method of blind marking: each attestor first publishes a hash of the mark and a secret value, and reveals the mark only after all commitments are in. Marks are therefore independent.</dd>
<dt id="decentralised-assessment">Decentralised assessment</dt><dd>Assessment by independent assessors whose results a verifier may accept or not, with no central body that accredits. Sanad does not accredit.</dd>
<dt id="evidence">Evidence</dt><dd>A typed record that backs a claim: practice runs that can be replayed, a live sitting, reviewed work, or peer review.</dd>
<dt id="hidden-skills">Hidden skills</dt><dd>Prerequisite skills inferred from a demonstrated skill by following the skill graph. They are always labelled inferred, carry their derivation, and stay private until the holder publishes them.</dd>
<dt id="level">Level</dt><dd>An integer from 0 to 5: none, aware, guided, independent, fluent and transferring to new problems, expert.</dd>
<dt id="policy">Policy</dt><dd>The verifier's own rules: how many attestors, whether a live sitting is required, how fast evidence ages, which attestors are trusted.</dd>
<dt id="recognition-function">Recognition function</dt><dd>The published, deterministic function that takes a policy, a claim, evidence and attestations and returns a level, a confidence, a status and an ordered explanation.</dd>
<dt id="skill-graph">Skill graph</dt><dd>An open, versioned, directed acyclic graph of skills with prerequisite edges and crosswalks to other vocabularies.</dd>
<dt id="transparency-log">Transparency log</dt><dd>An append-only Merkle log of attestation hashes with signed checkpoints and inclusion and consistency proofs.</dd>
<dt id="verifier">Verifier</dt><dd>Anyone who runs the recognition function on a bundle under their own policy.</dd>
</dl>
