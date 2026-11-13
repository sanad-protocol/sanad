# Sanad v0.2 (draft): an open protocol for recomputable recognition of skills

Document: SANAD-SPEC-0.2-draft (algorithm string `sanad-0.1`, unchanged) · Status: **draft, open for comment** · Date: 13 November 2026. This revision brings the text in step with the reference code and the engine (field names, hash coverage, commit form, chain rule, `bundleHash`, month length), adds the sitting-evidence schema, the static bundle directory, checkpoint publication and witnesses, and revocation, and marks in section 15 what is specified but not built. Version 7 November 2026 of this text was SANAD-SPEC-0.1. · Author and founder: Dr. Arash Kermani Kolankeh, interim steward

Sanad (a short word for a document and the chain of support behind it) is to be stewarded by the Open Sanad Foundation (UAE, in preparation); until it exists the author acts as interim steward. Nothing here is accreditation: Sanad practises **decentralised assessment**. It does not accredit anyone and it does not decide what a verifier must accept. A reference implementation with conformance vectors (`reference/` in the project repository) and an explainer (hosted by the Kamangir project for now) accompany this specification. The key words MUST, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

## 0. In one page
A qualification is not a certificate; it is a **chain**: a *claim* about a skill, backed by *evidence*, which is judged by *attestors* who sign what they saw and declare their conflicts of interest. Anyone can fetch the chain and run the same published function, the **recognition function**, with **their own policy**, and get a level, a confidence and a step-by-step explanation. Nothing has to be taken on trust from the issuer; what a verifier does have to choose is which attestors, and how much evidence, it requires. The protocol has no coin and no central authority. Verification is by recomputation, without a gatekeeper; the scarce resource is credible assessment, which the protocol does not create but makes visible.

Non-goals: ranking people; proving honesty (a person can still be helped off-camera); replacing legal recognition (degrees remain what states and institutions say they are); defining a payment system.

## 0.1 Scope and normative references
**Scope.** This document specifies the data model, the canonical form, the recognition function, the transparency log and the conformance rules. Sections 0, 1, 7, 10 (except the no-ranking rule), 12, 14 and 15 are informative; sections 3, 4, 5, 6, 8, 9 (conflict declaration), 10 (no-ranking rule) and 11 are normative.
**Normative references** (sources in Appendix B): RFC 2119 and RFC 8174 (key words); RFC 8785 (JSON Canonicalization Scheme: the canonical JSON of section 4 is that scheme); RFC 8032 (EdDSA); RFC 7515 (JWS); W3C Verifiable Credentials Data Model 2.0; W3C Decentralized Identifiers; W3C Bitstring Status List; FIPS 180-4 (SHA-256).

## 1. Principles
1. **Recomputable.** Every recognised level MUST be derivable by a deterministic public function from public or holder-disclosed data. No hidden scores.
2. **Verifier-side policy.** The issuer does not say "recognised". The verifier applies its own policy to the same evidence. Two verifiers may legitimately disagree; both can show why.
3. **Explainable.** The function returns an ordered explanation: each rule, its inputs, its effect.
4. **Evidence is typed and graded by independence.** Self-run practice is worth less than a sitting watched by independent examiners.
5. **No token, no speculation, no ranking.** Matching is opt-in and never ranks people.
6. **Privacy by default.** The holder controls what is published. Inferred skills are private until the holder publishes them.
7. **Honest wording.** Statuses follow a published stage ladder (stage 0, a self-declared keepsake, to stage 5, an award by an institution with the legal authority to make it); a Sanad result never uses the words accredited or certified by Sanad.
8. **Built on existing standards.** W3C Verifiable Credentials 2.0, W3C DIDs and the W3C Bitstring Status List are used now; Open Badges 3.0 (AchievementCredential) and SD-JWT VC for selective disclosure are **later** (section 15); the skill vocabulary is crosswalked to ESCO, MSC2020 and EQF. 

## 2. Terms
- **Skill**: a node of the open concept graph (a versioned, hash-pinned directed acyclic graph of skills), id like `analysis.limits.epsilon-delta`, with crosswalks `{esco?, msc?, eqf?}`.
- **Level**: integer 0..5: 0 none, 1 aware, 2 guided, 3 independent, 4 fluent and transfers to new problems, 5 expert (can teach and extend).
- **Claim**: "subject S has skill K at level L as of date D".
- **Evidence**: a typed record backing a claim (section 3.3).
- **Attestation**: a signed statement by an **attestor** about one evidence item (section 3.4).
- **Policy**: the verifier's rules (section 3.5).
- **Recognition result**: output of the function (section 5).
- **Transparency log**: an append-only Merkle log of attestation hashes (section 8).

## 3. Data model (JSON, canonicalised per section 4)
This section describes the data exactly as the reference core and the engine write it for algorithm `sanad-0.1`. Where version 0.1 of this text named a field differently (`evidenceId`, `reveal`, `sig`, `claimId`, `takenOn`), the names below are the ones in use and are normative.
### 3.1 Skill
`{ "id": "analysis.limits.epsilon-delta", "title": "...", "prereq": ["..."], "xwalk": { "msc": "26A03", "eqf": 6 } }`. The concept graph is a DAG; the recognition function (R8) reads prerequisites through a graph the verifier supplies. **Later (not built):** a pinned `graphHash` and a DAG check. A template names its skill by `skill.id` only.
### 3.2 Claim
In a bundle the claim is three members: `subject`, `skill` and `claimedLevel` (integer 0..5). The subject is a pseudonymous URN: `urn:uuid:<lower-case RFC 4122 UUID>` or `urn:sanad:subject:<32 to 64 lower-case hex characters>`; a name is never put there. (The v0.1 claim record with `claimedOn` and `graphHash` is not used.)
### 3.3 Evidence
`{ "id", "kind", "date", "summary", "body", "hash" }`, six members and no others. `id` is `<assessmentId>.<key>`. `kind` is `auto`, `sitting`, `artifact` or `peer`. `date` is `YYYY-MM-DD`. `summary` is human text and is not hashed. `body` is a JSON object that contains the members `kind` and `date` with the same values as the item (so that both are covered by the hash). **`hash` = SHA-256 of the canonical form of `body`** (section 4.2).
- **auto**: `body.autoLevel`, an integer 0..5, the level a replay of the seeded exercises yields. Without it the item fails R1.
- **sitting**: members below. Every member is optional in the protocol; a template may require some (`requireRecordingHash`, `requireStrokeLogHead`, `requireIdentityAssurance` on its evidence item), and a verifier warns when one is absent. Members that are present MUST have the stated form.

| member | form | meaning |
|---|---|---|
| `sittingId` | string matching `^[A-Za-z0-9._:-]{1,200}$` | identifies the sitting; required when `identityAssurance` is present |
| `paperFingerprint` | 64 lower-case hex | SHA-256 over the question paper as given |
| `strokeLogHead` | 64 lower-case hex | head of the SHA-256 hash chain over the pen strokes written during the sitting |
| `recordingSha256` | 64 lower-case hex | SHA-256 of the **plain** recording file; requires `recordingBytes` |
| `recordingCipherSha256` | 64 lower-case hex | SHA-256 of the encrypted file the organiser may hold; requires `recordingSha256` |
| `recordingBytes` | positive integer | size of the plain recording; requires `recordingSha256` |
| `identityAssurance` | object, section 3.3.1 | how identity was checked |
| `publication` | `{ "scope": "hashes" or "bundle", "date": "YYYY-MM-DD", "url"?: http(s) URL }` | where the candidate chose to publish: only hashes, or the whole bundle; `url` is the base of the static mirror |

The hashes are fixed **before the first attestor commits**: the engine accepts them by `addEvidence`, which refuses once any commit exists. **A recording is never part of the public chain.** It is held by the candidate or deleted (retention D+90 is procedural); afterwards the hash proves only that a file with that content existed, and it proves nothing about what the file showed.
- **artifact**: `{ "artifactSha256", "description" }` by convention; not checked by the protocol. **peer**: free JSON.

#### 3.3.1 Identity assurance
`{ "level", "method", "checkedBy", "date", "candidateKey", "signature" }`, six members. `level`: `A0` (nobody but the candidate vouches), `A1` (an examiner or registrar checked a document or knew the person), `A2` (checked against an official document, in person or by a registrar who holds a copy). `method`: a short token `^[a-z0-9][a-z0-9._-]{0,63}$`. `checkedBy`: the DID of the checker. `date`: `YYYY-MM-DD`. `candidateKey`: the candidate's Ed25519 public key as multibase (`z` and base58btc of the 32 raw bytes). `signature`: a detached JWS (section 4.3) with `typ` `sanad-identity+jws` by `checkedBy`, valid on `date`, over `{ "type": "sanad-identity", "sittingId", "level", "method", "checkedBy", "date", "candidateKey" }`. A level states how identity was checked, never that the candidate was honest. Which checkers a verifier believes is the verifier's choice; `minIdentityLevel` is a verifier option.
### 3.4 Attestation
Twelve members and no others: `id, attestor, evidence, level, role, conflictDeclared, date, signature, commit, nonce, prev, hash`.
- `id` is `<assessmentId>.aNN` (`a01`, `a02`, ...); `attestor` a DID; `evidence` the id of the evidence item attested; `level` an integer 0..5; `role` a string; `conflictDeclared` a boolean; `date` `YYYY-MM-DD`.
- **Commit-reveal.** `nonce` is 22 to 128 base64url characters. `commit` = SHA-256 of the canonical form of `{ "attestor", "evidence", "level", "nonce" }` (64 lower-case hex). The attestor publishes `commit` before any reveal; the reveal is the `level` and `nonce`. (Version 0.1 wrote "sha256 of level|nonce"; that form is not used: binding the attestor and the evidence stops a commit from being copied.)
- `signature` is the attestor's detached JWS with `typ` `sanad-attestation+jws` over the canonical form of `{ id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce }`, i.e. **without `prev`, `hash` and `signature`** (the attestor cannot know `prev` when signing). It must verify with a key of `attestor` valid on `date` (section 4.4). (The conformance vectors of the core use the placeholder `unsigned-v0.1:<hash>` and are verified without signatures.)
- `prev` and `hash`: attestations are ordered by `id` (section 4.5); `prev` is `GENESIS` for the first and otherwise the `hash` of the previous one; `hash` = SHA-256 of the canonical form of the attestation **without `hash` and `signature`** (that is, `id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce, prev`).
- **Attestor statistics** `{ "sittings": n, "agreement": 0..1 }` are an input of the recognition function. In `sanad-0.1` they are **supplied by the issuer** in the member `attestors` and **cannot be recomputed from the log** (the log holds hashes only). A verifier that sets a threshold on them MUST either supply its own statistics or accept the issuer's knowingly. A public, recomputable ledger of statistics is **later** (needs a privacy decision).
### 3.5 Policy (chosen by the verifier)
All eight members are required and range-checked: `minAttestors` (integer >= 1), `requireLive` (boolean), `halfLifeMonths` (number > 0), `minAttestorSittings` (number >= 0), `minAgreement` (0..1), `maxInferenceDepth` (integer >= 0), `inferenceDecay` (0..1), `asOf` (`YYYY-MM-DD`, the evaluation day; never the clock). A template carries a *recommended* policy with an `id`; the verifier is free to use another, and a credential never says "recognised" by itself.
### 3.6 The credential document
```
{ "@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential", "SanadCredential"],
  "id": "urn:uuid:...", "issuer": "<DID>", "validFrom": "<UTC date-time YYYY-MM-DDTHH:MM:SS.mmmZ>",
  "credentialSubject": { "id": <subject>, "skill": <skill id>, "claimedLevel": n },
  "evidence": [{ "type": ["Evidence", "SanadBundle"], "id": "urn:sanad:bundle:<bundleHash>", "bundleHash": "<hex>", "alg": "sanad-0.1" }],
  "credentialStatus": { ... },            // optional, section 8.3
  "sanad": { "bundle": { "skill", "claimedLevel", "subject", "evidence": [...], "attestations": [...], "attestors": { "<DID>": { "sittings", "agreement" } } },
             "template": { "id", "hash" }, "assessment": "<assessment id>",
             "process": { "invited", "committed", "revealed", "missing": [ids], "late": [ids], "notCommitted": [ids], "removed"?: [ids], "shortfall"?: [text], "evidenceAdded"?: [evidence ids] },
             "policy": { "id", + the seven policy members },
             "log": { "logId", "logKey", "entries": [{ "index", "leaf" }], "proofs": [{ "index", "size", "proof": [hex] }], "checkpoint": { "payload", "jws" } },
             "dids": [{ "id", "versions": [...] }] },
  "proof": { "type": "SanadDetachedJws", "verificationMethod": "<kid>", "created": "<= validFrom>", "jws": "..." } }
```
Every object above has a **closed member set**: a verifier MUST refuse a document with a missing or an extra member (members marked optional may be absent). The document is not processed as JSON-LD and is not claimed to be an Open Badges 3.0 AchievementCredential (**later**). `proof.jws` has `typ` `sanad-credential+jws` and covers the document without `proof`; `proof.created` equals `validFrom`; its key must be valid on the day of `validFrom`.
`process` records what happened: `invited` attestors, `committed`, `revealed`; `missing` lists attestations that committed but did not reveal, `late` those among them whose reveal came after the deadline, `notCommitted` those invited who never committed. A verifier checks `revealed` equals the number of attestations in the bundle, `revealed <= committed <= invited`, `missing` has `committed - revealed` entries, `notCommitted` has `invited - committed`, every `late` is also `missing`, and no `missing` id is in the bundle. `shortfall` (text) is present only if the operator finalized below the template minimum on purpose.

## 4. Canonical form, hashes, signatures
1. **Canonical JSON** is the JSON Canonicalization Scheme of RFC 8785: UTF-8, object members sorted by key in UTF-16 code unit order, no insignificant whitespace, strings escaped as in ECMAScript `JSON.stringify`, **numbers written as ECMAScript `Number` to string** (shortest round-trip form; `1`, `0.91`, `1e+21`). Members whose value is undefined do not exist. Numbers beyond 2^53, NaN, Infinity and lone surrogates are not valid input (I-JSON, RFC 7493).
2. **Hash**: SHA-256 (FIPS 180-4) of the canonical bytes, written as 64 lower-case hex characters. `evidence.hash` covers `body` only (3.3); `attestation.hash` covers the attestation without `hash` and `signature` (3.4).
3. **Detached JWS.** Every signature is a compact JWS (RFC 7515) with detached payload: `BASE64URL(header) + ".." + BASE64URL(signature)`, base64url without padding and only in its canonical encoding. The header is the canonical JSON of exactly `{ "alg": "EdDSA", "kid": <kid>, "typ": <typ> }` (these three members and no others; the decoded header bytes must equal the canonical form). The signing input is `BASE64URL(header) + "." + BASE64URL(canonical JSON of the payload)`. The signature is Ed25519 (RFC 8032) of 64 bytes. A verifier MUST be strict: reject a signature whose scalar S is not less than the group order, reject non-canonical encodings, and reject public keys of small order (the identity and the other torsion points). A JWS is accepted only if its `typ` is the expected one and its `kid` begins with `<signer DID>#`. The `typ` values:

| `typ` | signer | payload |
|---|---|---|
| `sanad-commit+jws` | attestor | `{ type: "sanad-commit", assessment, attestationId, attestor, evidence, role, commit, templateHash }` |
| `sanad-attestation+jws` | attestor | the attestation without `prev`, `hash`, `signature` |
| `sanad-credential+jws` | issuer | the credential without `proof` |
| `sanad-checkpoint+jws` | log operator | `{ logId, size, rootHash, timestamp }` |
| `sanad-cosignature+jws` | witness | section 8.2 |
| `sanad-status-list+jws` | issuer | the status list credential without `proof` |
| `sanad-identity+jws` | identity checker | section 3.3.1 |
| `sanad-issuer-card+jws` | issuer | the issuer card without `proof` (6.1) |
| `sanad-did-update+jws` | a key valid in the previous version | `{ did, ...the new version }` |

4. **Keys and DIDs.** A signer is a DID. **did:key**: `did:key:z` + base58btc (Bitcoin alphabet; each leading zero byte is a leading `1`) of the bytes `0xed 0x01` followed by the 32-byte Ed25519 public key; its verification method id is `<did>#<the part after did:key:>`; it resolves by itself and cannot rotate. **Any other DID** (for example `did:web:example.org`) has a **DID history**, `{ "id": <DID>, "versions": [ { "version": n, "validFrom": "YYYY-MM-DD", "keys": [ { "id": "#k1", "publicKeyMultibase": "z..." } ], "revoked": [ { "id": "#k1", "from": "YYYY-MM-DD" } ] } ] }` (version numbers 1, 2, ... without gaps; a version has exactly these four members; `publicKeyMultibase` is `z` + base58btc of the 32 raw bytes). Version `n+1` is accepted only with a `sanad-did-update+jws` by a key valid in version `n`. **A key is valid on date D** if it is listed in the latest version whose `validFrom <= D`, and no version lists a revocation of that key id with `from <= D`. The verification method id is `<DID><key id>` (for example `did:web:x.example#k1`). A statement made on date D is checked with the key named by its `kid`, valid on D (an attestation: its `date`; a checkpoint: the day of its `timestamp`; the credential: the day of `validFrom`). Limits on one history: at most 16 versions, 8 keys per version, 16 revocations per version. A DID history that arrives inside a credential is the issuer's own claim: a verifier MUST NOT trust a key from it unless the verifier pinned that key or holds the history itself.
5. **Order and chain.** `evidence` and `attestations` are sorted by `id` in UTF-16 code unit order before hashing and chaining. The attestation chain is defined in 3.4. **`bundleHash`** = SHA-256 of the canonical form of `{ "alg": "sanad-0.1", "skill", "claimedLevel", "subject", "evidence": [all evidence objects, sorted], "attestations": [all attestation objects, sorted] }`, each complete (with `hash` and `signature`). `attestors` (statistics) is outside the hash because a verifier may replace it; it is inside the issuer's signature. Altering any mark, signature or evidence member changes `bundleHash`.
6. **Pins.** A DID is a name, not a key. A verifier decides whom it trusts: the issuer DID, the log key DID and the log id, and, for non-`did:key` identities, the keys. A report that did not pin the issuer and the log key MUST NOT be called verified.

## 5. The recognition function (normative)
`recognise(policy, credential, attestorStats, graph) -> Result`. The function MUST be deterministic: inputs are sorted by id before use, there is no randomness and no clock (the evaluation date is `policy.asOf`). Version string: `sanad-0.1`. Arithmetic is IEEE-754 binary64; numeric results are rounded to 3 decimals, and an implementation conforms if every numeric result is within 0.001 of the value in the test vectors (this removes dependence on a particular maths library). Ages are measured in months of **30.4375 days** (365.25 / 12) between the evidence date and `policy.asOf` (a calendar-day difference). Intermediate values are not rounded; the confidence is rounded to 3 decimals as `Math.round(x * 1000) / 1000`.

**Definitions used below.** *Human attestor*: an attestor with a DID other than the pseudo-attestor `replay`. *Qualifying evidence*: evidence of kind `sitting` or `artifact` (the kinds that need independent human attestors). *Admissible*: not dropped by R1 or R2.
- **R1 integrity**: drop any evidence or attestation that fails one of these checks, and record each drop with its reason. Evidence: the kind is known, the date is a real calendar date, `hash` equals the hash of `body`, and an `auto` item has `body.autoLevel` 0..5. Attestation (in id order): the attestor is not the reserved name `replay`; `level` is an integer 0..5; `hash` equals the recomputed hash; `commit` equals the commitment recomputed from `attestor, evidence, level, nonce`; **the signature verifies** (when the verifier checks signatures, as every conforming verifier of engine credentials does; the reference vectors use placeholder signatures and skip this check); `prev` equals `GENESIS` for the first attestation in id order and otherwise the `hash` recorded in the previous attestation; **a second attestation by the same attestor on the same evidence item is dropped** (only the first, in id order, counts); the evidence it attests is present and itself intact; the date is a real calendar date. **A chain link fails only for the attestation whose own `prev` is wrong**; its successor is judged by its own `prev` against the stored hash of the failing attestation, so an honest successor is not dropped.
- **R2 admissibility**: drop an attestation if `conflictDeclared`; or, for a human attestor, if the attestor has fewer than `minAttestorSittings` sittings or agreement below `minAgreement` (a missing entry in the attestor statistics counts as 0 sittings and 0 agreement); drop evidence older than 4 half-lives, and evidence dated after `policy.asOf`.
- **R3 age factor**: `a = 0.5 ^ (ageMonths / halfLifeMonths)` for each evidence item.
- **R4 per-evidence level**: lower median of the admissible attested levels for that evidence item, capped by the kind (auto 3, peer 3, artifact 4, sitting 5). Automatic records (`auto`) have no human attestor: their replayed level is stored in the hashed evidence body (`autoLevel`) and is treated as one pseudo-attestation by `replay`, exempt from the attestor thresholds of R2 and not counted in R5.
- **R5 independence**: let `n` be the number of distinct admissible human attestors on qualifying evidence. Peer reviewers do not count in `n`. If `n < minAttestors`, or `requireLive` and there is no admissible `sitting`, the status is `provisional` and the level is limited to the best automatic or peer level (0 if there is none; at most 3). Otherwise the status is `recognised`. Automatic and peer evidence alone never lead to `recognised`. The result also carries `attestedLevel`: the level R6 would give if the policy were met, so that a reader can see what was attested although the policy was not satisfied.
- **R6 level**: `recognisedLevel = min(claimedLevel, lower median of the per-evidence levels of the qualifying evidence)`.
- **R7 confidence**: for each admissible evidence item and each of its admissible attestations, form a term `w x a x g`, where `w` is the weight of the kind (sitting 0.6 per attestor, artifact 0.3, auto 0.25, peer 0.15), `a` the age factor of R3, and `g` an agreement factor. The spread of the admissible attested levels of **that evidence item** (maximum minus minimum) decides `g`: `g = 1` if the spread is at most 1, otherwise the weights of that evidence item are halved (`g = 0.5`). Confidence = `1 - product(1 - term)` over all terms, rounded to 3 decimals. With no admissible evidence the status is `not-recognised` and the confidence is 0.
- **R8 inference** (hidden skills): for each prerequisite `p` of the recognised skill at graph distance `d <= maxInferenceDepth` (shortest backward path), and with no direct claim: `inferredLevel = max(0, level - d)` and `inferredConfidence = confidence * decay^d`. Inferred skills are always labelled INFERRED, carry their derivation path, and MUST NOT be published without the holder's choice.
The result is `{ "alg": "sanad-0.1", "policyId", "status", "level", "attestedLevel", "confidence", "explanation": [{ "rule", "summary", "inputs", "effect" }], "inferred": [...] }`. The explanation is part of the result so that a human can audit it line by line. The attestor statistics used in R2 are an input of the function (3.4): the issuer supplies them, and a verifier may replace them with statistics it pins itself. Conformance is tested by `vectors.json` (section 11).

## 6. Carrying a Sanad bundle in a credential, and publishing it as static files
The credential (3.6) is shaped after W3C Verifiable Credentials 2.0; its one `evidence` entry names the bundle: `{ "type": ["Evidence", "SanadBundle"], "id": "urn:sanad:bundle:<bundleHash>", "bundleHash", "alg": "sanad-0.1" }`. The `id` MUST be `urn:sanad:bundle:` followed by `bundleHash`. The credential contains the whole bundle, so it verifies on its own. (**Later, not built:** Open Badges 3.0 AchievementCredential output, a W3C Data Integrity proof suite, SD-JWT VC; none of them is claimed.)
### 6.1 The static directory and the URL scheme
Only three kinds of things are public: hashes, signed checkpoints and credential bundles. They are plain static files that anyone may copy; a free public git repository is a sufficient mirror. No video is ever part of the public chain. With a base URL or directory `<base>`:

| path | content |
|---|---|
| `<base>/issuer.json` | issuer card: `{ type: "sanad-issuer-card", version: 1, alg, issuer, logId, logKey, base, bundles, checkpoints, status, dids, updated, proof }`; `proof` = `{ type: "SanadDetachedJws", verificationMethod, jws }` with `typ` `sanad-issuer-card+jws` over the card without `proof` |
| `<base>/bundles/<bundleHash>/` | one bundle; **`urn:sanad:bundle:<bundleHash>` resolves to this directory** |
| `.../credential.json` | the credential |
| `.../evidence.json`, `attestations.json`, `log.json`, `checkpoint.json`, `dids.json` | the same data as `sanad.bundle.evidence`, `sanad.bundle.attestations`, `{ logId, logKey, entries, proofs }`, `sanad.log.checkpoint`, `sanad.dids`, split out for readers |
| `.../consistency.json` | list of `{ from: { size, rootHash }, to: { checkpoint }, proof }`: proofs that the log at the credential's checkpoint is a prefix of later signed checkpoints |
| `.../witnesses.json` (optional) | list of `{ checkpoint, cosignature }` (8.2) |
| `.../status.json` (optional) | snapshot of the status list at export time (8.3); fetch the list again for a current answer |
| `.../manifest.json` | `{ type: "sanad-bundle-manifest", version: 1, bundleHash, files: { "<name>": <SHA-256 hex of the file bytes> } }` listing every other file in the directory except itself |
| `.../README.md` | how to read and verify the directory |
| `<base>/checkpoints/<size>.json`, `latest.json`, `index.json` | 8.2 |
| `<base>/status/revocation.json` | the status list credential (8.3) |

The manifest protects a mirror against accidental damage; it is **not** trust (anyone can recompute it). A verifier of a directory MUST check that every file listed in the manifest exists and has the recorded SHA-256, that the directory name equals `bundleHash` of `credential.json`, that each split file equals the corresponding part of the credential (canonical forms equal), that the issuer card (if present) names the credential's issuer, log id and log key and verifies under the issuer's key, and then everything in section 11 on `credential.json`. Verification of a directory needs no server and no network.

## 7. Skill graph, crosswalks, inference
The concept graph is versioned and hash-pinned. Crosswalks to ESCO, MSC2020 and EQF are advisory metadata: they let other systems index the same claim; they are not used by the function. Inference follows prerequisite edges only; it never invents a skill outside the graph and never raises a level above the directly demonstrated one.

## 8. Transparency log, checkpoints, witnesses, revocation
### 8.1 The log
An append-only list of **leaves**. A leaf is the canonical JSON text of exactly `{ "kind", "ref", "ts" }`: `kind` is `commit`, `attestation`, `missing-reveal` or `bundle`; `ref` is 64 lower-case hex; `ts` an ISO 8601 date-time. `ref` is: for `commit`, the SHA-256 of the canonical commit statement (the payload of `sanad-commit+jws`); for `attestation`, the attestation `hash`; for `missing-reveal`, the `commit` hash of the attestor who did not reveal; for `bundle`, the `bundleHash`. The log reveals hashes only, never content or names. The tree is the Merkle tree of **RFC 9162 section 2.1**: leaf hash = SHA-256(0x00 || leaf bytes as UTF-8), node hash = SHA-256(0x01 || left || right), hashes as 64 lower-case hex, the empty tree's root is SHA-256 of the empty string; inclusion proofs (2.1.3) and consistency proofs (2.1.4) are lists of hex hashes verified as in the RFC. (Version 0.1 logged only attestation hashes; commits, missing reveals and bundles are logged too, so that "every commit came before the first reveal" can be shown.)
### 8.2 Checkpoints, publication, witnesses
A **checkpoint** is `{ "payload": { "logId", "size", "rootHash", "timestamp" }, "jws" }` (exactly those four payload members; `jws` has `typ` `sanad-checkpoint+jws` and is made with the log key; the key must be valid on the day of `timestamp`). `logId` names one log.
**Publication.** The log operator writes checkpoints as static files under `<base>/checkpoints/`: `<size>.json` = `{ "checkpoint", "previous": { "size", "rootHash" } | null, "consistency": [hex] }` where `consistency` is the RFC 9162 consistency proof from the previous published checkpoint to this one; `latest.json` has the content of the newest file; `index.json` is the list `[ { size, timestamp, rootHash } ]` in order. The operator publishes on demand and at least daily (a scheduled job). An empty log is not published. A smaller or different log than a published checkpoint is an error, never published. Optionally the operator also publishes `<base>/log/entries.json` (every entry: hashes and times, no names), so that any party can rebuild the tree.
**Witness.** Any party can be a witness. One run: fetch `latest.json`; check the checkpoint signature with the **pinned** log key; if the witness stored a checkpoint before, require the same size to have the same root, a smaller size to be refused, and a larger size to be reached by a chain of published checkpoints whose `previous` links start at the stored checkpoint and whose consistency proofs all verify; then cosign. A failure is an **alert** (evidence kept), never a silent skip. The cosignature is `{ "witness": <DID>, "witnessedAt": <ISO date-time>, "jws" }` with `typ` `sanad-cosignature+jws` over `{ type: "sanad-cosignature", logId, size, rootHash, timestamp, logKey, witness, witnessedAt }` (the checkpoint's own members, the log key and the witness), valid with a key of the witness on the day of `witnessedAt`. A witness keeps `<witnessBase>/<logId>/<size>.json` = `{ checkpoint, cosignature, chain }` and `latest.json`; the log key it trusts is pinned in `pin.json`. A witness directory may live in a public git repository updated by a scheduled job; the git history is the mirror.
**Counting witnesses.** A verifier that requires N witnesses pins a list of witness DIDs. A witness counts once if its cosigned checkpoint (a) is signed by the log key, (b) has the credential's `logId`, (c) has a valid cosignature, and (d) is either the credential's checkpoint itself (same size, same root) or a larger one with a valid RFC 9162 consistency proof from the credential's checkpoint (a smaller one, or the same size with another root, does not count). Cosignatures by witnesses the verifier did not pin count for nothing. **Not built (later):** Bitcoin anchoring with OpenTimestamps; gossip between witnesses.
### 8.3 Revocation
A credential MAY carry `credentialStatus`: `{ "id": "<list URL>#<index>", "type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "<decimal string>", "statusListCredential": "<list URL>" }` (exactly these five members). The list is a W3C Bitstring Status List credential published at the list URL, issued by the **same issuer**: `{ "@context": [VC 2.0], "id": <list URL>, "type": ["VerifiableCredential", "BitstringStatusListCredential"], "issuer", "validFrom", "validUntil", "credentialSubject": { "id": "<list URL>#list", "type": "BitstringStatusList", "statusPurpose": "revocation", "encodedList" }, "proof" }`, with `proof.jws` of `typ` `sanad-status-list+jws` over the document without `proof`. `encodedList` is `u` (multibase base64url, no padding) followed by the **GZIP**-compressed bitstring of at least 131,072 bits; **bit 0 is the most significant bit of the first byte**; a set bit means revoked. A verifier fetches the list fresh, checks the signature, the issuer, that `validFrom <= now <= validUntil` (an expired list is refused: a stale list can hide a revocation) and that the bit at `statusListIndex` is clear. A verifier that was not given the list reports "revocation not checked" and MAY refuse to call the credential verified. Suspension and message bits (`statusSize` above 1) are not used. Revocation withdraws a credential; it does not change the log.

## 9. Attestors and trust
Anyone may become an attestor by publishing a DID and signing. **Nobody vets them for the protocol**, and independence is not enforced by it: it rests on declared conflicts of interest, blind marking and the verifier's policy. Verifiers choose by policy (minimum sittings, agreement rate, named allow-lists, or a web of trust). Attestor statistics are issuer-supplied in `sanad-0.1` and are not recomputable from the log (3.4). Conflicts of interest MUST be declared (family, employer, paid tutor, same cohort); an undeclared conflict that is discovered should be recorded as a signed dispute against the attestor (**later**, section 15). Assignment to a sitting SHOULD be random from the pool; marks are blind until all commits are in.

## 10. Privacy, discovery and matching
- **Selective disclosure**: the holder presents an SD-JWT VC revealing only chosen claims, for example "linear algebra at level 4 or above, recognised under policy P", not the sittings or the date.
- **Skill cards**: an opt-in public record `{ skill, level range, policy id, contact route }` signed by the holder. There is no central profile database; indexers (any party) crawl only cards that holders publish.
- **Hidden skills**: computed locally in the holder's browser from the holder's own bundles (R8). Shown to the holder first, marked INFERRED.
- **Mediated introduction**: contact goes to a pseudonymous inbox. Requesters MUST be identified organisations or individuals; rate limits deter spam (how an index enforces them is outside this specification, which defines no payment system); the holder sees who is asking and why before anything is revealed.
- **No ranking**: indexes return sets that satisfy a query, not ordered "best candidates"; protocol-conformant tools MUST NOT produce a score of a person across skills.
- **Law**: data minimisation and consent (GDPR, UAE PDPL; check both); recordings are not part of the public chain (retention D+90 is procedural); EU AI Act: tools that rank or filter job applicants are high-risk, so employment matching needs human oversight, transparency and a legal review before launch.

## 11. Conformance and test vectors
Conformance classes: **Verifier** (checks a credential and a directory as below, runs the function and prints the explanation), **Issuer** (emits bundles and credentials), **Attestor** (signs blind marks), **Log** (serves checkpoints and proofs). The class **Indexer** (no-ranking rule) is specified in 10 but **not built and has no vectors**; it is not yet a testable class. `vectors.json` (core) contains the policy, claim, evidence, attestations and expected result for: no evidence; auto only; one examiner when two are needed; two agreeing examiners; disagreeing examiners; a declared conflict; stale evidence; a tampered hash; depth-2 inference; strict versus loose policy over the same evidence. The engine vectors (`engine/vectors/engine-*.json`) pin bundle hashes, log roots and refusal codes; they are generated by the engine and are regression vectors. An independent check is a second implementation written from this text only.

### 11.1 What a Verifier checks on a credential
A verifier MUST perform these checks, in this order, and report each as pass or fail. It MUST NOT report a credential as verified unless every check passes.
1. **shape**: the closed member sets of 3.6, 3.3, 3.4; limits: at most 200 attestations, 200 evidence items, 2000 log entries, 100 DID histories; ids unique; `claimedLevel` an integer 0..5.
2. **issuer-proof**: `proof.jws` verifies (4.3) under a key of `issuer` valid on the day of `validFrom`, with `kid` equal to `proof.verificationMethod` and `proof.created` equal to `validFrom`.
3. **bundle-hash**: the recomputed `bundleHash` (4.5) equals `evidence[0].bundleHash`; `evidence[0].id` is `urn:sanad:bundle:` plus it; `alg` is `sanad-0.1`; `credentialSubject` equals `{ id: subject, skill, claimedLevel }` of the bundle.
4. **evidence-consistency**: for every evidence item, `body.kind` and `body.date` equal `kind` and `date`.
5. **sitting-evidence**: for every `sitting` item the members of 3.3 that are present are well formed; an `identityAssurance` signature verifies (3.3.1); if the verifier set `minIdentityLevel`, every sitting has at least that level; if the verifier holds the template and the template requires a member that is absent, this fails unless `process.shortfall` records it. Absent `paperFingerprint`, `strokeLogHead` or `recordingSha256` is a warning.
6. **ids**: every evidence and attestation id begins with `<sanad.assessment>.`.
7. **attestor-signatures**: every attestation signature verifies (3.4) under a key valid on its `date`.
8. **log**: the checkpoint signature verifies with `sanad.log.logKey`, valid on the day of its timestamp; `checkpoint.payload.logId` equals `sanad.log.logId`; each embedded entry's `leaf` parses as a valid leaf whose canonical form equals the text; each has an inclusion proof for `size` equal to the checkpoint size, verifying against the checkpoint root; the set of leaves contains an `attestation` leaf for every attestation `hash` and a `bundle` leaf for `bundleHash`. If the verifier pinned log ids, `logId` is among them.
9. **trusted-issuer, trusted-log-key**: `issuer` and `logKey` are among the DIDs the verifier pinned. **did-histories**: every key taken from a DID history embedded in the credential is pinned by the verifier (or the verifier holds the history).
10. **process**: the consistency rules of 3.6.
11. **template** (only if the verifier holds the template): its hash equals `sanad.template.hash`; every attestation role is in the template; every evidence item is an item of the template with the same kind and none is missing; the template minimum of attestors per non-auto evidence item (attestors with a declared conflict do not count) and, for a live-sitting template, a revealed mark on a sitting, are met unless `process.shortfall` records the shortfall.
12. **policy**: the verifier supplied a complete policy (3.5). If it has `minAttestorSittings > 0` or `minAgreement > 0` and the verifier supplied no statistics of its own, this fails unless the verifier accepts the issuer's statistics knowingly.
13. **revocation** (8.3), when the credential has `credentialStatus` and the verifier supplied the list; **witnesses** (8.2), when the verifier requires N.
14. Then the **recognition function** (5) runs with the verifier's policy, the bundle, the attestor statistics in force and the verifier's signature results (R1 drops an attestation whose signature fails). If a check failed, the result is labelled unverified.

### 11.2 What a Verifier checks on a directory
6.1, then 11.1 on `credential.json`, plus: each `consistency.json` entry starts from the credential's checkpoint (same size and root), its `to` checkpoint is signed by the log key and has the same `logId`, and its proof verifies.

## 12. Threats and mitigations
| Threat | Mitigation in v0.1 | Residual risk |
|---|---|---|
| Collusion of examiners | random assignment; blind commit-reveal; agreement statistics (issuer-supplied); disputes (later); policy can require attestors from different institutions | a determined cartel; needs audits |
| Sybil attestors | no trust by default; policies require sittings and agreement history; verifiers use allow-lists | slow to bootstrap |
| Candidate cheating (help off camera) | desk camera, room check, human observation; the chain says what was observed, not honesty | cannot be eliminated |
| Identity (someone else sits) | attestors record how identity was checked; stage ladder wording | weak without ID checks |
| Tampering | hash chain, signatures, transparency log, published checkpoints and witnesses (Bitcoin timestamp: later) | key compromise |
| Goodhart (teaching to the test) | endless seeded items; sittings use fresh questions | slow |
| Algorithmic bias in matching | transparent function, no ranking, human oversight, legal review | unknown unknowns |
| Key loss | holder backup, DID rotation, re-attestation by two attestors | usability |
| Exclusion by cost | sponsor-a-seat fund; auto and peer evidence remain free (provisional) | funding |

## 13. Governance and evolution
Versioned (`sanad-MAJOR.MINOR`); a change that alters a vector's expected result is a new minor version; the text is frozen per version. The specification text is released under CC BY 4.0 and the reference code under Apache-2.0. The name "Sanad" is intended to be held by the Foundation (interim: the steward, in trust); a trademark application is planned and is not yet filed. Anyone whose implementation passes the vectors may say that it conforms. The path to a standard: public specification, reference implementation, conformance suite, at least three independent implementers, then a W3C Community Group or a 1EdTech workgroup. Sanad does not declare itself a standard; adoption does. Until a Working Group exists, the Sanad Foundation is the steward, under the governance charter published with this specification.

## 14. Open questions (need a decision or a lawyer)
1. Who runs the first transparency log, and who audits it? 2. Level descriptors 0..5: adopt EQF-aligned wording or keep project-specific wording? 3. How many attestors for a sitting is the minimum honest number (1, 2, 3)? 4. Attestor payment versus independence (flat fee already decided). 5. Appeals: who judges a dispute (ombudsperson) and how is the outcome recorded. 6. Sanctions and access: attestors and holders in sanctioned places (legal advice). 7. Are policy templates published (`school-loose`, `uni-strict`)? 8. Retention of recordings versus a public chain (D+90).

## 15. Specified but not built ("later")
These are described in this document or intended by it, and are **not** in engine 0.3. Nothing here is claimed to work:
- Open Badges 3.0 AchievementCredential output and a W3C Data Integrity proof suite (`eddsa-jcs-2022`); the credential is "shaped after" VC 2.0 only.
- SD-JWT VC selective disclosure (section 10).
- Skill cards, indexers and the Indexer conformance class; no vectors exist.
- A pinned skill graph (`graphHash`) and a DAG check (3.1).
- OpenTimestamps anchoring of checkpoints; gossip between witnesses.
- Signed disputes against attestors (section 9) and a public, recomputable ledger of attestor statistics (3.4).
- Suspension and multi-bit status messages (8.3).
- A commit statement carried in the credential, so that commit-before-reveal is provable to a third party without the operator's word; today the order is shown by the log leaves and attested by the operator.

## Appendix A: worked example
The example is invented: no person, sitting or attestor in it is real. It is the sample credential of the reference implementation (`reference/src/sample.ts`) and is reproduced by `node reference/verify.mjs` and by the explainer.

Claim: subject `urn:uuid:7c1f0b2e-sample-learner`, skill `B09` (a first course in real analysis), claimed level 4, as of 2026-11-07. Evidence: E1 auto (40 seeded exercises, level 3), E2 live sitting with attestations att-01 (examiner, level 4) and att-02 (examiner, level 4), E3 artifact (three written proofs) with att-03 (reviewer, level 4), E4 peer review with att-04 (level 3). Attestor statistics: examiner 1 has 14 sittings and agreement 0.91, examiner 2 has 9 and 0.88, the reviewer has 6 and 0.80, the peer has 1 and 0.70. Default policy: minAttestors 2, requireLive true, halfLifeMonths 24, minAttestorSittings 3, minAgreement 0.6, maxInferenceDepth 2, inferenceDecay 0.7.

Result: status `recognised`, level 4, confidence 0.909. R1 finds every hash and reveal intact. R2 ignores att-04 (the peer has 1 sitting, the policy needs 3), so E4 does not count. R3 gives age factors 0.950, 0.983 and 0.966 to E1, E2 and E3. R4 gives levels 3 (E1), 4 (E2, lower median of 4 and 4) and 4 (E3). R5 finds three distinct admissible attestors and a live sitting, so independence is met. R6: level = lower of the claim (4) and the lower median of the sitting and artifact levels (4) = 4. R7: confidence = 1 − the product of (1 − weight × age factor × agreement factor) over the four items = 0.909.

Variations the reader can try: with a policy that requires three attestors on a sitting, the status becomes `provisional` and the level is capped at 3; changing one mark after sealing makes R1 drop it and lowers the confidence.

## Appendix B: references
Sources as of 7 November 2026. Only status statements that were checked against the source are made.

- RFC 2119 and RFC 8174 (key words): <https://www.rfc-editor.org/rfc/rfc2119>, <https://www.rfc-editor.org/rfc/rfc8174>.
- RFC 8785, JSON Canonicalization Scheme (Informational, June 2020, independent submission): <https://www.rfc-editor.org/rfc/rfc8785>.
- RFC 8032 (EdDSA): <https://www.rfc-editor.org/rfc/rfc8032>. RFC 7515 (JSON Web Signature): <https://www.rfc-editor.org/rfc/rfc7515>.
- FIPS 180-4 (SHA-256): <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>.
- W3C Verifiable Credentials Data Model 2.0: <https://www.w3.org/TR/vc-data-model-2.0/>. W3C Decentralized Identifiers: <https://www.w3.org/TR/did-core/>.
- W3C Bitstring Status List v1.0, W3C Recommendation of 15 May 2025: <https://www.w3.org/TR/2025/REC-vc-bitstring-status-list-20250515/>.
- RFC 9901, Selective Disclosure for JSON Web Tokens (Proposed Standard, November 2025): <https://www.rfc-editor.org/rfc/rfc9901>. SD-JWT-based Verifiable Credentials remained an Internet-Draft (draft-ietf-oauth-sd-jwt-vc, revision 13 of 6 November 2025) when last checked: <https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/>.
- 1EdTech Open Badges 3.0 (final, 17 June 2024): <https://www.imsglobal.org/spec/ob/v3p0/>.
- RFC 6962 and RFC 9162 (Certificate Transparency): <https://www.rfc-editor.org/rfc/rfc6962>, <https://www.rfc-editor.org/rfc/rfc9162>.
- OpenTimestamps: <https://opentimestamps.org/>.
- European Qualifications Framework: <https://europass.europa.eu/en/europass-digital-tools/european-qualifications-framework>. ESCO: <https://esco.ec.europa.eu/>. Mathematics Subject Classification 2020: <https://msc2020.org/>.
- Regulation (EU) 2024/1689 (Artificial Intelligence Act), Annex III on high-risk systems in employment: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>.
- UAE Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data (citation of the law; consult the official legislation portal for the text).
