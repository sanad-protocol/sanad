# Spec decisions needed before v1.0

These points came out of an independent review of the engine (reference implementation of `sanad-0.1`). Each one changes a format or the meaning of a rule that the specification (SANAD-SPEC-0.1) or the 20 conformance vectors make visible. The engine therefore leaves its behaviour unchanged and records the options here. The steward decides; implementers should not decide them locally.

For each item: what the problem is, the options, and a recommendation. A recommendation is not a decision.

## 1. Carrying commit statements in the bundle (blind ordering is only operator-attested)

**Problem.** The credential holds attestations (with their reveals) but not the signed commit statements. The log holds a leaf for each commit (`ref` = hash of the commit statement), but the statement itself is not in the credential, so a verifier cannot show from the credential alone that every commit was signed before any reveal. Blind marking is thus attested by the operator, not proved to a third party.

**Options.**
- A. Leave as is and state it (current text in README and DESIGN section 11).
- B. Add the signed commit statements (payload and JWS) to the bundle and cover them by `bundleHash`; verifiers check each signature, that each reveal matches its commit, and that the commit leaves precede the first attestation leaf in the log. This changes `bundleHash` and the credential format.
- C. Carry only the commit leaf inclusion proofs and statements outside the bundle (a sidecar document), leaving `bundleHash` unchanged.

**Recommendation.** B for v1.0 (new algorithm string or a bundle version), with A stated until then. C is a stop-gap.

## 2. What the attestor signature should cover

**Problem.** The attestor signs the attestation without `prev`, `hash` and `signature`: `{ id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce }`. It does not cover the evidence content hash, the assessment id or the template hash. A signature made for one assessment could in principle be presented in another that reuses ids and evidence ids; the commit statement (signed) does name `assessment` and `templateHash`, the attestation does not.

**Options.**
- A. Leave as is.
- B. Add `evidenceHash` (the hash of the evidence item), `assessment` and `templateHash` to the signed attestation statement.
- C. Sign the commit statement and treat the attestation as its reveal (so the signed commit carries those bindings and the attestation is bound to it by the `commit` hash).

**Recommendation.** B, together with decision 1 (both change the attestation statement and so the attestation hash).

## 3. `conflictDeclared` (and `date`) in the commit preimage

**Problem.** The commit is `SHA-256(canonical({ attestor, evidence, level, nonce }))`. `conflictDeclared` and `date` are chosen at the reveal, after the first reveal is public, so an attestor can withdraw a mark by declaring a conflict after seeing another attestor's mark (rule R2 then ignores it).

**Finding of the review round.** Adding `conflictDeclared` to the preimage passes the 20 core vectors (they are sealed at run time, so their commits are recomputed). It was **not** adopted because it changes the commit of every credential issued under `sanad-0.1`: such credentials would fail R1 under the new code, and an independent implementation following the specification text (or the published commit form) would disagree under the same algorithm string.

**Options.**
- A. Leave and document (current).
- B. Add `conflictDeclared` (and optionally `date`) to the preimage under a new algorithm string `sanad-0.2`, with the old form still verifiable under `sanad-0.1`.
- C. Forbid changing `conflictDeclared` between commit and reveal by putting it in the signed commit statement (not the hash), which needs decision 2.

**Recommendation.** B or C at the same time as decisions 1 and 2, in one format version.

## 4. Attestor statistics made verifiable

**Problem.** Specification section 9 says statistics are public and recomputable from the log. The log holds hashes only, so `sittings` and `agreement` are issuer-supplied and cannot be recomputed. The engine now makes verifiers say so (`attestorStats`, `allowIssuerStatistics`).

**Options.**
- A. Change the specification to say they are issuer-supplied, with verifier-supplied overrides (current engine behaviour).
- B. Publish a statistics ledger (attestor DID, assessment, evidence, level, bundle hash) next to the log so that anyone can recompute; this exposes marks and DIDs publicly and needs a privacy decision.
- C. Make statistics a signed statement by each attestor's home institution or a web of trust, outside the engine.

**Recommendation.** A for 1.0 (honest wording), B only after a privacy review.

## 5. Agreement definition

**Problem.** "Agreement" is not defined for an even number of other attestors or for no co-attestor, and the specification says "same sittings" while the engine counts every evidence item with at least two marks.

**Options.** A: keep the engine's definition (lower median of the others, 0 with none, all evidence kinds) and write it into the specification. B: restrict to sittings. C: use a different measure (for example mean absolute difference).

**Recommendation.** A, restated in the specification with a vector.

## 6. Credential proof format

**Problem.** The engine secures the credential with a detached JWS over the canonical document. The specification does not say how. The W3C Data Integrity suite `eddsa-jcs-2022` is the standard choice for JCS-canonicalized JSON.

**Options.** A: keep the detached JWS and specify it. B: adopt `eddsa-jcs-2022` (proof object with `proofValue`, multibase). C: support both.

**Recommendation.** B or C before claiming interoperability with Verifiable Credentials tooling; until then the document must not be described as validating against VC or Open Badges processors.

## 7. Evidence hash coverage

**Problem.** The specification says the evidence hash covers the object without `hash` and `sig`; the reference hashes only `body`, so `kind` and `date` are outside it. The engine mirrors `kind` and `date` into the body and covers them by the bundle hash.

**Options.** A: keep the mirror and specify it. B: hash the whole evidence object without `hash` (changes every evidence hash; the vectors are sealed at run time so they would still pass, but old credentials would not verify).

**Recommendation.** B in the same format version as decisions 1 to 3.

## 8. Level 6 and a host-level field

**Problem.** Levels run 0 to 5. A host with six grades has no place for its native grade in the credential except the engine's optional convention of writing it into the nonce (`nm-<native>-<random>`), which is hidden until the reveal and then public.

**Options.** A: keep the convention. B: add an optional, signed `native` member to the attestation statement and the commit preimage. C: widen levels to 0 to 6.

**Recommendation.** A for now; B with decisions 2 and 3 if hosts need it. C is a breaking change to the recognition function and not recommended.

## 9. `did:web` proof of control

**Problem.** The engine registers a `did:web` key history as given by the operator (trust on first registration). It does not fetch `https://<domain>/.well-known/did.json` and does not prove control of the domain.

**Options.** A: keep, and require verifiers to pin keys (done in the engine). B: fetch and compare the DID document at registration and on a schedule (needs network access and a policy for failures). C: restrict to `did:key` for attestors.

**Recommendation.** A for 1.0; B as an optional operator feature, never in the verifier path.

## 10. Deviations in rules R5, R8 and the level cap, and the month length

**Problem.** The review compared the reference function with the specification text and found: R8 (inference) runs on a provisional result in the engine but the text suggests only on recognised ones; R5 counts distinct attestors without looking at their role (peer versus examiner); the provisional level cap is the best automatic or peer level, which the text does not state explicitly; the month is 30.4375 days in the reference and 30.436875 in the specification text (an independent checker used 365.2425/12).

**Options.** For each, either change the text to match the reference (and add a vector) or change the reference (the 20 vectors constrain most of these). The month length differs by less than the vector tolerance and should simply be fixed in the text.

**Recommendation.** Change the text to the reference for R5, the provisional cap and the month (30.4375), add one vector for each, and decide R8 on provisional results explicitly (recommended: do not run R8 on a provisional result).
