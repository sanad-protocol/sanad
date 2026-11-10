# Sanad engine 0.2: design

This document describes the Sanad engine: a small program that runs assessments end to end and produces Sanad credentials that any verifier can recompute. It implements algorithm `sanad-0.1` of SANAD-SPEC-0.1 and does not change it. Package version 0.2.0; algorithm string `sanad-0.1`.

## 1. Scope

The engine does:

- hold **assessment templates** (skill, levels, rubric, evidence plan, attestor requirements, recommended verifier policy, live-sitting flag);
- run **one assessment**: create it, invite attestors by DID, accept **blind commits**, then **reveals**, enforce deadlines, record missing and late reveals;
- build the **evidence chain** and seal a **credential** with the core library (`reference/`), sign it with the issuer key, and append hashes to a **transparency log** (Merkle tree with inclusion and consistency proofs, signed checkpoints);
- **verify** a credential: issuer proof, bundle hash, attestor signatures, log inclusion, then the recognition function under the verifier's own policy;
- offer the same through a library, an HTTP API (`node:http`), a CLI and a small demonstration page.

The engine does not: vet attestors (spec section 9: nobody vets them for the protocol); run a live room, video or proctoring; take payments; fetch DID documents over the network; publish skill cards or run an index; implement selective disclosure (SD-JWT) or a Bitstring Status List; anchor checkpoints in OpenTimestamps; rank people. It is not accreditation and claims nothing about the honesty of a sitting: a chain says what was observed.

Runtime dependencies: none. Node 22 or later (`node:crypto` Ed25519, `node:http`, `node:fs`; `node:sqlite` only if present). `esbuild` and `vitest` are development tools of the repository, used to build the single-file bundles and to run tests.

## 2. Packages and files

| Path | Role |
|---|---|
| `reference/` (package `@sanad-protocol/core` 0.2.0) | Canonical JSON, SHA-256, sealing helpers, rules R1-R8, the 20 conformance vectors, CLI `sanad` (`verify`, `run-vectors`). Kept in place (least disruptive: the site build and the vitest suite import it). `dist/sanad-reference.mjs` and `dist/sanad-reference.d.ts` are committed. |
| `engine/` (package `@sanad-protocol/engine` 0.2.0) | Plain ES modules (`.mjs`), no build step needed to run. `dist/sanad-engine.mjs` is a single-file bundle of core and engine for vendoring, built by `engine/build.mjs`, committed, with its SHA-256 printed. |
| `engine/src/keys.mjs` | Ed25519 key helpers, `did:key`, detached JWS, key resolver with DID documents (rotation, revocation) |
| `engine/src/template.mjs` | Template schema and validator, template hash |
| `engine/src/commit.mjs` | Commit and attestation statements, commit/reveal verification |
| `engine/src/assessment.mjs` | Assessment state machine (create, invite, commit, reveal, finalize), deadlines, independence checks |
| `engine/src/bundle.mjs` | Evidence chain, credential sealing, bundle hash, issuer proof, `verifyCredential` |
| `engine/src/log.mjs` | Transparency log (RFC 9162 Merkle tree, proofs, checkpoints, hash-chained entries) |
| `engine/src/stats.mjs` | Attestor statistics (sittings, agreement) derived from finalized assessments |
| `engine/src/store/` | Storage interface; `memory`, `file` (JSON files and JSON lines), `sqlite` (when `node:sqlite` exists) |
| `engine/src/engine.mjs` | `createEngine(...)`: the library entry that ties the parts together (the exam-service adapter surface) |
| `engine/src/http.mjs`, `engine/static/` | HTTP API and the demonstration page |
| `engine/src/cli.mjs`, `engine/bin/sanad-engine` | CLI |
| `engine/src/demo-keys.mjs` | **Demonstration only**: generates and keeps attestor private keys so that a scripted run can play several attestors. Never imported by the engine core, HTTP server or library entry. |
| `engine/examples/` | Three templates with scripted end-to-end runs |
| `engine/vectors/engine-*.json` | Engine vectors (deterministic keys and clock) |
| `engine/test/` | Unit, property and end-to-end tests (vitest) |

## 3. Data formats

Everything is JSON, hashed as SHA-256 over the canonical form of the core library (RFC 8785 for the value types used here: strings, integers, booleans, null, arrays, objects).

**Identifiers.** Attestor and issuer ids are DIDs. `did:key` (Ed25519, multicodec `0xed01`, base58btc, prefix `z`) works with no registry; it cannot rotate. Any other DID (for example `did:web:...`) must be registered with the engine as a **DID document history** (section 5). The verification method id (`kid`) is `<did>#<fragment>`; for `did:key` the fragment is the multibase key.

**Detached JWS.** Every signature is a JWS (RFC 7515) in compact form with a detached payload: `BASE64URL(header) + ".." + BASE64URL(signature)`. The header is the canonical JSON of `{ "alg": "EdDSA", "kid": <kid>, "typ": <type> }`. The signing input is `BASE64URL(header) + "." + BASE64URL(UTF-8(canonical(payload)))`. The `typ` separates statement kinds, so a signature made for one kind is never accepted for another:

| `typ` | Signed by | Payload |
|---|---|---|
| `sanad-commit+jws` | attestor | `{ type: "sanad-commit", assessment, attestationId, attestor, evidence, role, commit, templateHash }` |
| `sanad-attestation+jws` | attestor | the attestation without `prev`, `hash`, `signature`: `{ id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce }` |
| `sanad-credential+jws` | issuer | the credential document without `proof` |
| `sanad-checkpoint+jws` | log operator | `{ logId, size, rootHash, timestamp }` |
| `sanad-did-update+jws` | a key valid in the previous DID document version | the new version |

A verifier refuses a JWS whose `alg` is not `EdDSA`, whose `typ` differs from the expected one, whose `kid` does not belong to the expected signer (the attestor of the attestation, the issuer of the credential), whose key was not valid on the statement's date, or whose header has any other member.

**Commit.** As in the reference code and the vectors: `commit = SHA-256(canonical({ attestor, evidence, level, nonce }))`. The engine creates a 128-bit random nonce (22 base64url characters) and refuses shorter nonces on new commits (the level space is 0..5, so the nonce is what hides the mark).

**Attestation.** The reference shape (`id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce, prev, hash, signature`). `signature` holds the attestor's `sanad-attestation+jws`. `prev` and `hash` are added by the issuer at sealing (chain in id order, `GENESIS` first), so an attestor can sign before the order is known. A sealed attestation with any other member is refused by the engine verifier (unhashed members would be malleable).

**Evidence.** The reference shape (`id, kind, date, summary, body, hash`, `hash = SHA-256(canonical(body))`). Because the reference hash covers the body only, the engine copies `kind` and `date` into the body (`body.kind`, `body.date`) and its verifier requires them to match; the bundle hash covers the whole evidence objects.

**Bundle.** The core credential object `{ skill, claimedLevel, subject, evidence, attestations, attestors }`. `bundleHash = SHA-256(canonical({ alg: "sanad-0.1", skill, claimedLevel, subject, evidence, attestations }))` with evidence and attestations sorted by id and complete (including `hash` and `signature`). `attestors` (statistics) is outside the bundle hash because it is a verifier input that a verifier may replace with statistics it pins itself; it is inside the issuer's signature.

**Credential document.** Shaped after W3C VC 2.0; it is not processed as JSON-LD and is not claimed to validate against Open Badges 3.0:

```
{ "@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential", "SanadCredential"],
  "id": "urn:uuid:...", "issuer": "<did>", "validFrom": "<ISO date-time>",
  "credentialSubject": { "id": "<pseudonymous subject>", "skill": "<id>", "claimedLevel": n },
  "evidence": [{ "type": ["Evidence", "SanadBundle"], "id": "urn:sanad:bundle:<bundleHash>", "bundleHash": "...", "alg": "sanad-0.1" }],
  "sanad": { "bundle": {...}, "template": { "id", "hash" }, "assessment": "<id>",
             "process": { "invited": n, "committed": n, "revealed": n, "missing": [ids], "late": [ids] },
             "policy": { recommended policy of the template, with id },
             "log": { "logId", "entries": [{ "index", "leaf" }], "checkpoint": {...}, "proofs": [...] } },
  "proof": { "type": "SanadDetachedJws", "verificationMethod": "<kid>", "created": "<ISO date-time>", "jws": "..." } }
```

## 4. One assessment, step by step

1. **Template.** The operator registers a template; the engine validates it and pins `templateHash`.
2. **Create.** `createAssessment({ templateId, subject, claimedLevel, evidence, commitBy, revealBy })`. Evidence items follow the template's evidence plan; ids are `<assessmentId>.E<n>`. The subject id is pseudonymous (`urn:uuid:` or another URN); names never enter the engine.
3. **Invite.** `invite({ assessment, attestor, role, evidence })` assigns an attestation id `<assessmentId>.a<nn>`. Refused: an attestor already invited on the same evidence (`duplicate_attestor`), the subject as attestor, a role the template does not allow, more attestors than the template's maximum, a DID the resolver cannot resolve.
4. **Commit (blind).** The attestor computes the commit from its level and a fresh nonce, signs a `sanad-commit+jws`, and sends `{ attestationId, payload, jws }`. Accepted only from the invited attestor, once (`already_committed`, even for an identical commit), before `commitBy` (`commit_closed`). The commit is appended to the log (leaf kind `commit`).
5. **Reveal.** Opens when every invited attestor has committed or `commitBy` has passed (`reveal_not_open` before). The attestor sends the attestation statement and its `sanad-attestation+jws`. Checks: signature and key validity on `date`; statement fields equal the invitation; `commit` equals the stored commit; `commitOf(statement)` equals the commit (`commit_mismatch`); `level` an integer 0..5 allowed by the template; `date` not before the evidence date and not after the reveal day. After `revealBy` the reveal is refused and recorded as `late`.
6. **Finalize.** Allowed when every commit is revealed or `revealBy` has passed. Commits without a reveal are recorded as `missing` (log leaf kind `missing-reveal`); they produce no attestation. Attestor statistics are computed from earlier finalized assessments (section 7). The engine seals evidence and attestations (chain and hashes per the core), computes `bundleHash`, appends each attestation hash and the bundle hash to the log, signs the credential and stores it.
7. **Verify.** Anyone runs `verifyCredential(doc, { policy, resolver, log? })`: issuer proof, bundle hash, evidence `kind`/`date` consistency, closed member sets, attestor signatures (passed to the core as a signature check, so a failing signature drops that attestation under R1 with its reason), log inclusion proofs against the embedded or a fresh checkpoint, then `recognise` and `infer` with the verifier's policy (the template's policy is only a recommendation). The report lists every check and the full explanation.

## 5. Keys

Ed25519 throughout (RFC 8032, `node:crypto`; WebCrypto `Ed25519` in the demonstration page). **Attestors hold their private keys.** The engine, its HTTP server and its library entry never receive, store or generate an attestor's private key; they receive signed statements only. The issuer key and the log key belong to the operator who runs the engine (`sanad-engine init` writes them to files with mode 0600). `demo-keys.mjs` is a separate helper for scripted demonstrations and tests.

Rotation and revocation: a DID document history is a list of versions `{ version, validFrom, keys: [{ id, publicKeyMultibase }], revoked: [{ id, from }] }`; version 1 is registered by the operator (trust on first registration); every later version must carry a `sanad-did-update+jws` by a key that is valid in the previous version. A key verifies a statement dated D if it is listed in the version in force on D and is not revoked from a day on or before D. `did:key` has no rotation; a lost or compromised `did:key` is replaced by a new identity.

## 6. Storage

Interface (synchronous, single process): `get(collection, id)`, `put(collection, id, value)`, `list(collection)` (sorted by id), `append(stream, value) -> index`, `read(stream, from, to)`, `size(stream)`, `close()`. Collections: `templates`, `assessments`, `dids`, `credentials`. Streams: `log`, `events`. Adapters: `memory`; `file` (one JSON file per record written through a temporary file and rename; streams as JSON lines appended with `fsync`; ids are checked against `^[A-Za-z0-9._:-]{1,200}$` so no path can escape the directory); `sqlite` (two tables, optional table prefix, accepts an existing `DatabaseSync`, so a host service can keep the engine in its own database). Private keys are never put in a store.

## 7. Transparency log and attestor statistics

The log is an RFC 9162 Merkle tree (leaf hash `SHA-256(0x00 || leaf)`, node hash `SHA-256(0x01 || left || right)`). A leaf is the UTF-8 canonical JSON `{ kind, ref, ts }` where `kind` is `commit`, `attestation`, `missing-reveal` or `bundle`, `ref` a SHA-256 hex and `ts` an ISO date-time: hashes only, no names or content. Each stored entry also carries `prev`, the hash of the previous entry, so a damaged file is detected locally. The log offers signed checkpoints, inclusion proofs and consistency proofs with their verification functions.

Attestor statistics (spec 3.4): `sittings` is the number of finalized assessments in which the attestor revealed a mark on `sitting` evidence; `agreement` is the share of the attestor's marks that lie within one level of the lower median of the other attestors' marks on the same evidence item, over the items that had at least one other mark; with no such item it is 0.

## 8. HTTP API

JSON over `node:http`, body limit 256 KiB, `content-type: application/json` required on POST. Operator routes need `authorization: Bearer <operator token>` (compared in constant time). Attestor routes are open because the body is signed. Errors are `{ "error": code, "message": text }`.

| Method and path | Who | Purpose |
|---|---|---|
| `GET /healthz` | anyone | liveness |
| `GET /v1/info` | anyone | engine version, algorithm, issuer DID, log id |
| `POST /v1/templates`, `GET /v1/templates`, `GET /v1/templates/:id` | operator / anyone | register and read templates |
| `POST /v1/dids`, `GET /v1/dids/:did` | operator / anyone | register a DID document history or a signed update |
| `POST /v1/assessments`, `GET /v1/assessments/:id` | operator / anyone | create; public view (no nonces before reveal) |
| `POST /v1/assessments/:id/invite` | operator | invite an attestor |
| `POST /v1/assessments/:id/commit` | attestor (signed) | blind commit |
| `POST /v1/assessments/:id/reveal` | attestor (signed) | reveal |
| `POST /v1/assessments/:id/finalize` | operator | seal and issue the credential |
| `GET /v1/credentials/:id` | anyone | the credential |
| `POST /v1/verify` | anyone | verification report for a posted credential and optional policy |
| `GET /v1/log/checkpoint`, `/v1/log/entries`, `/v1/log/inclusion`, `/v1/log/consistency` | anyone | log |
| `GET /v1/attestors/:did/stats` | anyone | derived statistics |
| `GET /` | anyone | the demonstration page (strict CSP, no external code) |

## 9. CLI

`sanad-engine init [--dir]`, `keygen --out <file>` (demonstration attestor key), `template add <file>`, `create-assessment --template <id> --subject <id> --level <n> [--evidence <file>] [--commit-by] [--reveal-by]`, `invite <assessment> --attestor <did> --evidence <id> [--role]`, `commit <assessment> <attestationId> --key <file> --level <n>` (keeps the nonce in a local file next to the key), `reveal <assessment> <attestationId> --key <file>`, `finalize <assessment> [--out]`, `verify <credential.json> [--policy <file>]`, `log checkpoint|inclusion|consistency`, `serve [--port] [--host]`. The core CLI `sanad` offers `verify` (recognition only, no signature checks, and it says so) and `run-vectors [file]`.

## 10. Templates

```
{ "id": "maths-oral-v1", "version": 1, "title": "...", "skill": { "id": "analysis.limits", "title": "..." },
  "levels": [{ "level": 0..5, "label": "..." }], "rubric": [{ "id", "criterion", "descriptors": { "<level>": "..." } }],
  "evidence": [{ "key": "E1", "kind": "sitting|artifact|auto|peer", "summary": "..." }],
  "attestors": { "min": 2, "max": 3, "roles": ["examiner"] },
  "liveSitting": true, "deadlines": { "commitHours": 24, "revealHours": 48 },
  "policy": { "id": "maths-oral-strict-1", ...the eight policy fields except asOf } }
```

The validator refuses unknown members, levels outside 0..5, a live-sitting template without `sitting` evidence, `min > max`, and a policy that would fail the core's own range checks.

## 11. Security considerations, and what is not claimed

- **Replay**: every signed payload names the assessment, the attestation id and its `typ`; commits are accepted once; HTTP has no session to replay. **Malleability**: closed member sets, canonical JSON, bundle hash over complete objects, `kind`/`date` mirrored into the hashed body. **Canonical form**: one implementation (core) is used by every module; numbers other than integers are not used in signed statements. **Key misuse**: `kid` must belong to the expected signer and be valid on the date; issuer and log keys are separate from each other. **Timing**: secrets compared in constant time (operator token); commits are public values.
- **Backdating with a stolen key**: a revoked key can still sign statements with an earlier date. The log time of the commit is the defence; the verifier report shows it. Not fully solved.
- The engine has had **no external cryptographic review** and **no independent implementation** checks its outputs; the Ed25519 and SHA-256 primitives are Node's. Collusion, help off camera and identity checks are outside what any software can prove (spec section 12).

## 12. Integrating an exam service (the adapter)

A host service keeps its own workflow (bookings, payments, rooms) and calls the library: `createEngine({ store, issuer: { did, kid, sign }, log, resolver, clock })`, then `registerTemplate`, `createAssessment`, `invite`, `commit`, `reveal`, `finalize`, `verifyCredential`, `stats`. It may share its SQLite database through the `sqlite` adapter with a table prefix. For portability the host **vendors** `engine/dist/sanad-engine.mjs` (one file, no dependencies) and records its SHA-256 and the source commit; a test in the host checks the hash. A path dependency on a local checkout is not portable and is not used.

The Kamangir network service (first host): an examiner's device key is the attestor key (`did:key` of the raw public key); the browser signs the commit and the attestation; the committee's sitting is one `sitting` evidence item; the credential is issued at the Registrar's release and given to the candidate through the status token. Kamangir levels run 1..6 while Sanad levels run 0..5: the mapping is part of the Kamangir template (provisional: identity up to 5, 6 to 5), and the native mark is bound into the nonce (`kn1.<native level>.<random>`) so that the two cannot drift apart. The mapping is an owner decision.

## 13. Test plan

The 20 core vectors pass unchanged (`node reference/verify.mjs`). New engine vectors, deterministic (keys from fixed seeds, fixed clock): `engine-commit-reveal` (honest run, expected bundle hash and recognition), `engine-tamper` (a mark changed after sealing; a changed evidence kind; a changed signature), `engine-late-reveal`, `engine-missing-reveal`, `engine-duplicate-attestor`, `engine-key-rotation`. Unit tests per module, property tests where cheap (Merkle proofs for every size up to 64; canonical round trips; commit binding), an end-to-end test with three attestors (honest, one whose mark is tampered after sealing, one who never reveals), the three examples, the HTTP API, the CLI, and a check that the committed bundles equal a fresh build. Site: `node test.mjs` and `npx vitest run`.

## 14. Open points (spec text versus the reference code; the spec is not edited)

1. **Commit form.** Spec 3.4: "sha256 of level|nonce". Reference and vectors: `SHA-256(canonical({attestor, evidence, level, nonce}))`. The engine follows the vectors (the binding to attestor and evidence also stops copying another attestor's commit).
2. **Field names.** Spec 3.4 names `evidenceId`, `reveal`, `sig`; reference uses `evidence`, `nonce`, `signature`, and adds `prev`. Spec 3.3 evidence fields (`claimId`, `takenOn`) differ from the reference (`date`, `summary`, `body`). The engine follows the reference.
3. **Evidence hash coverage.** Spec 4.2: the hash covers the object without `hash` and `sig`. Reference: the hash covers `body` only, so `kind` and `date` are outside it. The engine mirrors them into the body and covers them by the bundle hash.
4. **Month length.** Spec 5: 30.436875 days. Reference: 30.4375. The difference is below the 0.001 tolerance for the vectors but is a defect in one of the two texts.
5. **What a signature covers.** Spec 3.4: a JWS "over the canonical attestation". With the `prev` chain the attestor cannot know `prev` when signing; the engine signs the attestation without `prev`, `hash` and `signature`.
6. **Signature failure in R1.** R1 lists hash, commit-reveal and chain failures; it does not list a failed signature. The engine passes a signature check to the core, which then drops the attestation under R1 with the reason "signature". Without the check the core behaves exactly as in v0.1.
7. **`bundleHash`.** Spec 4.4 calls it the root hash of the claim-evidence-attestation tree without defining the tree; the engine's definition is in section 3.
8. **Agreement statistic.** "Median of the other attestors" does not say which median for an even count, nor what agreement is with no co-attestor; the engine uses the lower median and 0.
9. **Credential proof.** Spec 6 does not say how the credential is secured; the engine uses a detached JWS. A W3C Data Integrity suite (`eddsa-jcs-2022`) would be the standard choice and is a candidate for a later version.
10. **Log leaves.** Spec 8 logs attestation hashes; the engine also logs commits, missing reveals and bundle hashes, so that the order "all commits before any reveal" can be shown.
