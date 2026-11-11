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

## 10. Deviations in rules R5 and R8, the level cap, and the month length

**Problem.** A review compared the reference function with the specification text and found: R8 (inference) runs on a provisional result in the engine, while the text suggests only on recognised ones; R5 counts distinct attestors without looking at their role (peer versus examiner); the provisional level cap is the best automatic or peer level, which the text does not state; and the month is 30.4375 days in the reference and 30.436875 in the specification text.

**The month length is not a harmless rounding.** The two values differ by about 0.002 percent, but evidence age is compared with a hard threshold (four half-lives, rule R2). Evidence dated 1461 days before the evaluation day with a half-life of 12 months is exactly 48 months at 30.4375 days and is kept; at 30.436875 days it is 48.0003 months and is dropped. A test (`reference/src/core-review.test.ts`, "month length") pins the reference's behaviour at this boundary. The constant has not been changed.

**Options.** For each deviation, either change the text to match the reference (and add a vector) or change the reference (the 20 vectors constrain most of these). For the month: errata choosing one value, with a vector at the boundary.

**Recommendation.** Choose 30.4375 (365.25 / 12) in the text, add a boundary vector; change the text to the reference for R5 and the provisional cap and add a vector for each; decide R8 on provisional results explicitly (recommended: do not run R8 on a provisional result).

## 11. Three rule changes in the core relative to the v0.1 reference

**Problem.** The core (and so every credential evaluation by the engine) differs from the v0.1 reference in three rules, although the algorithm string is still `sanad-0.1`:
1. a second mark by the same attestor on one evidence item is dropped under R1 (v0.1 counted every mark, so one attestor could move the lower median by signing several times);
2. with the optional signature check, a failing signature drops the attestation under R1 (v0.1 did not check signatures, and R1 as written lists only hash, commit and chain failures);
3. a policy must be complete and in range and `claimedLevel` must be 0 to 5, otherwise the function refuses with an error (v0.1 computed a result from whatever it was given).

Smaller changes: the attestor name `replay` is reserved, statistics are read from own numeric properties, and an optional verifier allow-list exists. On credentials with duplicate marks the results differ from v0.1 (a review measured 2,500 of 20,000 random credentials); otherwise they match, and the 20 vectors match.

**Options.**
- A. Errata to v0.1: edit the v0.1 text to include these rules. Not possible without breaking the rule that the text of a version is frozen (SPEC section 10) and the deposited tag `spec-0.1-deposit-2026-11-07`.
- B. A new algorithm id `sanad-0.2` for the engine's rule set, with a new specification version stating the three rules, new vectors (duplicate marks, failing signatures, partial policy), and `sanad-0.1` kept as the literal v0.1 behaviour for old credentials.
- C. Revert the three rules and document the weaknesses of v0.1 (duplicate marks inflate the median, no signature check, silent defaults).

**Recommendation.** B. The v0.1 text must not be edited. Until then the documents say plainly that the engine's behaviour differs and name how.

## 12. Chain rule: what is dropped when a link fails

**Problem.** The specification (R1) says: when an attestation's `prev` is not the stored hash of its predecessor, that attestation, and therefore also its honest successor, is dropped. The core drops only the attestation whose own link fails; its successor still links to the stored hash of the (tampered) predecessor and is kept. In a reviewer's worked example the credential is recognised at level 3 with confidence 0.783 under the core rule and is provisional with confidence 0.464 under the literal text.

**Options.** A: change the text to the core's rule. B: change the core to the literal text (a conservative rule that loses honest attestations). C: drop the chain rule in favour of the bundle hash, which already covers every attestation.

**Recommendation.** A or C: the successor is intact, the bundle hash and the signatures already catch any change, and the literal rule punishes honest attestors. A test pins the current behaviour.

## 13. Normative verification limits

Documents beyond these numbers are refused by the engine's verifier: 200 attestations, 200 evidence items, 2000 log entries, 100 DID histories per credential; 16 versions per DID history; 8 keys and 16 revocations per version. A verifier that accepts more is exposed to unbounded work. **Options:** make these the normative limits of `sanad-0.2`, or state them as implementation limits. **Recommendation:** normative, with the numbers in the specification.

## 14. Ed25519 and JWS profile

The engine verifies Ed25519 strictly per RFC 8032 (the scalar `S` must be below the group order; point encodings must be canonical; the check is cofactorless) and refuses public keys of small order everywhere, including `did:key`. JWS is detached compact with a canonical-JSON header of exactly `alg`, `kid`, `typ`; base64url without padding and only the canonical encoding. **Recommendation:** put this profile in the specification; independent verifiers that accept more will disagree on adversarial input.

## 15. DID-history format and key validity

A history is `{ id, versions: [{ version, validFrom, keys: [{ id: "#frag", publicKeyMultibase }], revoked: [{ id, from }] }] }`; `kid` is `<did>#<frag>`; keys are `z` + base58btc of the raw 32-byte key (no multicodec prefix); a key verifies a statement dated D if it is listed in the version in force on D and no revocation of it has `from <= D`. Version 1 is registered by the operator; later versions are signed by a key valid in the previous one. **Open:** the date is the statement's own, so a key holder can backdate (not detected); a role for the log (a timestamp the verifier can check) is not specified. **Recommendation:** specify the format; decide whether commit time in a log the verifier trusts must bound the statement date.

## 16. Use of log timestamps

Log entries carry the operator's time (monotonic in the engine). No verifier rule uses them. Whether a statement's `date` must be consistent with the log time of its commit is undecided. **Recommendation:** decide together with decision 1.

## 17. Commit leaf `ref` and log leaf kinds

The leaf of kind `commit` has `ref = SHA-256(canonical(commit statement))` (the signed payload), not the `commit` hash. **Recommendation:** specify it with decision 1.

## 18. Range of `claimedLevel`

Integer 0 to 5, enforced by the core and by the engine's shape check. **Recommendation:** state it in the specification.

## 19. Effect of withheld reveals

A commit without a reveal is recorded as `missing` and produces no attestation; the other attestations are evaluated as if the missing attestor had not sat. An attestor who sees the others' marks can therefore withhold their own (and, after the first reveal, declare a conflict; decision 3). **Options:** accept and document; require a minimum number of reveals before any reveal is public (a threshold reveal); count missing reveals in the statistics. **Recommendation:** document now; consider a threshold reveal for v1.0.

## 20. Distinct attestors (R5) versus the per-item minimum

R5 counts distinct admissible attestors across qualifying evidence; the template minimum applies per evidence item. A credential can satisfy one and not the other. **Recommendation:** state both rules in the specification and add a vector.

## 21. Subject URN rule

The engine accepts `urn:uuid:<RFC 4122 UUID>` and `urn:sanad:subject:<hex>` only. **Recommendation:** specify as a guard rail; free-text evidence fields are public and must not hold personal data.

## 22. ECMAScript number formatting and duplicate keys

Canonical JSON follows RFC 8785, so numbers use the ECMAScript shortest round-trip form and keys are ordered by UTF-16 code units. Duplicate keys in an object are not defined in JSON text; the engine's parser keeps the last, and implementations may differ. **Recommendation:** require rejection of duplicate keys in credentials and statements and of numbers beyond 2^53.

## 23. Specification field names versus credentials

The specification names attestation fields `evidenceId`, `reveal`, `sig` and evidence fields `claimId`, `takenOn`; credentials use `evidence`, `nonce`, `signature`, `date`, `summary`, `body`. **Recommendation:** follow the credentials and correct the text in the next version.

## 24. Definition of `bundleHash` and the checkpoint key date

`bundleHash = SHA-256(canonical({ alg, skill, claimedLevel, subject, evidence, attestations }))` with both lists in id order and complete; `attestors` (statistics) is outside it. The checkpoint's signing key is checked against the checkpoint's own timestamp date. **Recommendation:** specify both; consider covering the statistics or the template hash by the bundle hash (decision 4).
