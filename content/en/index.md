---
key: home
lang: en
path: /
template: home
title: Sanad: an open protocol for recomputable recognition of skills
h1: Sanad: an open protocol for recomputable recognition of skills
description: Sanad is a draft open protocol. A qualification is a chain of claim, evidence and signed attestations that anyone can recompute under their own policy. No token, not accreditation.
lead: Sanad specifies a data model for claims, evidence and attestations, a deterministic recognition function that a verifier runs under its own policy, and a conformance suite with a reference implementation.
---

<ul class="cta">
<li><a class="primary" href="/spec/0.1/">Read the specification</a></li>
<li><a href="/conformance/">Run the test vectors</a></li>
<li><a href="/explainer/">Try the explainer</a></li>
<li><a href="/participate/">Participate</a></li>
</ul>

<!-- glance -->
- **What:** a data model and a deterministic recognition function for skills, with a public explanation for every result.
- **Who decides:** the verifier. Each employer, school or university applies its own published policy to the same evidence.
- **What it is not:** not a coin, not a ranking of people, not accreditation.
- **Status:** draft v0.1 for discussion. A reference implementation and 20 test vectors are published. Run by one person for now; a second steward is being appointed. See [Status and limits](/status/).
<!-- /glance -->

## The problem

Many people can do things they cannot prove. Papers are lost, institutions close, states stop recognising study, and a certificate says little about how it was earned. Employers and universities cannot easily check what stands behind a claim, so they trust brands and borders instead of evidence.

<!-- worked-example -->

## How it works

<ol class="steps wide">
<li><strong>Claim</strong>A person states a skill at a level, for example real analysis at level 4. The skill is a node in an open, versioned concept graph.</li>
<li><strong>Evidence</strong>The claim is backed by typed evidence: replayable practice runs, a live sitting watched by examiners, reviewed work, peer review.</li>
<li><strong>Attestation</strong>Attestors sign what they saw. Marks are committed blind before any is revealed, so that they are independent of one another.</li>
<li><strong>Recognition</strong>Anyone runs the published function with their own policy and gets a level, a confidence and a step-by-step explanation.</li>
</ol>

## Who it is for

<div class="cards wide linked">
<div><h3><a href="/for/learners/">Learners without portable proof</a></h3><p>Carry evidence that does not depend on one institution.</p></div>
<div><h3><a href="/for/examiners/">Examiners and assessors</a></h3><p>Sign what you saw; your record is public and recomputable.</p></div>
<div><h3><a href="/for/institutions/">Universities and employers</a></h3><p>Apply your own policy and show exactly why a result came out as it did.</p></div>
<div><h3><a href="/for/implementers/">Implementers</a></h3><p>Build a verifier, issuer, attestor, log or index; run the public vectors.</p></div>
<div><h3><a href="/for/funders/">Funders</a></h3><p>A lean plan, a risk register and what support would change.</p></div>
<div><h3><a href="/for/press/">Press</a></h3><p>A fact sheet, and what would show that Sanad is wrong.</p></div>
</div>

<div class="status-box">

### Status

Sanad is a **draft (v0.1)** for discussion. It has not been reviewed by a standards body, a lawyer or an external cryptographer. It uses **decentralised assessment**: it does not accredit anyone and does not decide what a verifier must accept. It has **no token** and no financial component. Until the Open Sanad Foundation (UAE) exists, the author, Dr. Arash Kermani Kolankeh, acts as interim steward; a second steward is being appointed, and the [governance charter](/governance/) limits what a single steward may do.

</div>

## Where to start

- Read the [specification](/spec/0.1/) (about 20 minutes) or its [PDF](/spec/SANAD-SPEC-0.1.pdf).
- Run `node reference/verify.mjs` from the [conformance page](/conformance/) to see 20 vectors pass.
- Open the [explainer](/explainer/) to change a verifier policy and watch the result and its explanation change.
- Read the [questions and answers](/faq/), the [roadmap](/roadmap/) and how to [participate](/participate/).
