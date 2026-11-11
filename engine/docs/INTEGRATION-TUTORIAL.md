# How to plug Sanad into any system

This tutorial shows how a platform (a course site, an exam centre, a guild, a school network) adds Sanad credentials without changing how it works today. The engine knows nothing about the platform, and the platform gets no special status in the protocol: it is one host among many.

Read first, in five lines:

- Sanad is decentralised assessment of skill, not accreditation. Nobody vets attestors for the protocol.
- A credential is a recomputable chain of what was observed. **Each verifier applies its own policy**; the policy inside a template is only a recommendation.
- Examiners commit to a mark blind, then reveal, so they cannot copy each other.
- **Attestors hold their own private keys.** The engine, the server and the library never receive or generate them.
- No names or personal data enter the engine. The protocol has no central authority, no token and no fee.

What is tested and what is not is marked **Tested** and **Untested** throughout; section 9 collects the untested items.

## 1. The three integration modes

| Mode | What the host runs | Good for | Tested |
|---|---|---|---|
| 1. Library, vendored single file | `import` of `dist/sanad-engine.mjs` inside the host process | Node hosts that want no extra service; one place to deploy | Yes: `engine/examples/toy-host.mjs` and its test use the bundle |
| 2. Sidecar HTTP service | `sanad-engine serve` beside the host; the host speaks JSON | Hosts in other languages; separating operator keys from the host | Yes: HTTP and CLI tests; no test from a non-Node client |
| 3. Verify only | `verifyCredential` (or `sanad-engine verify`) | Employers, schools, apps that only read credentials | Yes: library and CLI tests; the same function runs in both |

A host can combine them: issue with mode 2, and let third parties verify with mode 3.

## 2. The roles and who holds what

| Role | Holds | Never holds |
|---|---|---|
| **Attestor** (examiner, reviewer) | Own Ed25519 private key, the level and nonce between commit and reveal | |
| **Operator** (runs the engine) | Issuer key, log key, operator token | Any attestor private key |
| **Host** (the platform) | People, names, grades, bookings, payments; the link from a pseudonym to a person; checkpoints | |
| **Verifier** (anyone) | Its own policy, the issuer and log keys it chooses to trust | |

The attestor signs in their own client: a browser page (`engine/static/sanad-client.js`, WebCrypto), a CLI (`sanad-engine commit` and `reveal`, which keep the nonce next to the key file), or the host's own app. The host forwards the signed request; it cannot sign for the attestor and should not try to. If the host generates attestor keys for them, the host can forge marks and the "attestors hold their own keys" property is lost; do not do that.

## 3. The flow, whichever mode

1. The operator registers a **template** (section 6).
2. The host creates an **assessment** for a pseudonymous subject with its evidence items.
3. The host **invites** attestors by DID, one invitation per attestor per evidence item.
4. Each attestor **commits** (hash of attestor, evidence, level, nonce; signed), blind.
5. When every invited attestor has committed, or the commit deadline has passed, reveals open. Each attestor **reveals** level and nonce, signed.
6. The operator **finalizes** after all reveals or after the reveal deadline. Missing and late reveals are recorded, not hidden.
7. Anyone **verifies**, with their own policy.

## 4. Worked example against a toy host

`engine/examples/toy-host.mjs` is a toy course site in 70 lines. It is integration mode 1: it imports the committed bundle, `engine/dist/sanad-engine.mjs`. Its test (`engine/test/toy-host.test.mjs`) runs it. The key parts:

**Setup.** The host makes an engine with its own issuer and log keys and registers the template:

```js
import { createEngine, createMemoryStore, makeSigner, generateKeyPair } from './vendor/sanad-engine.mjs';

const issuer = makeSigner(generateKeyPair().privateKey);     // operator keys: store them safely, in a real host
const logSigner = makeSigner(generateKeyPair().privateKey);
const engine = createEngine({ store: createMemoryStore(), issuer, logSigner });
engine.registerTemplate(template);                           // see section 6
```

For anything beyond a demonstration use `createFileStore(dir)` or `createSqliteStore({ path })`; `createMemoryStore` forgets everything on exit.

**Pseudonyms.** The host keeps names; the engine gets only a URN:

```js
const pseudonym = 'urn:uuid:' + randomUUID();
hostDb.people.set('s-17', { name: 'Ada Example', pseudonym });   // the link lives in the host only
```

The engine refuses a subject that is not a URN (`bad_subject`). A URN is not proof of pseudonymity: do not put a name or an e-mail address inside it.

**A sitting.**

```js
const a = engine.createAssessment({
  templateId: template.id, subject: pseudonym, claimedLevel: gradeToLevel(5),
  evidence: [{ key: 'E1', date: '2026-03-01', summary: 'Oral sitting', body: { minutes: 40 } }],
});
const inv = engine.invite(a.id, { attestor: examinerDid, role: 'examiner', evidence: 'E1' });
```

**Commit and reveal (on the attestor's side).** In the toy host the same script plays the examiners with generated keys, which is what makes it a demonstration. A real examiner runs this on their own device:

```js
import { prepareCommit, prepareReveal } from './vendor/sanad-engine.mjs';

const view = await (await fetch(hostUrl + '/assessments/' + a.id)).json();       // the host forwards the public view
const { request, secret } = prepareCommit({ signer, assessment: view, attestationId: inv.attestationId, level: 4 });
await post('/commit', request);                    // keep `secret` on the device until the reveal
// ... later, when reveals are open:
await post('/reveal', prepareReveal({ signer, assessment: view, attestationId: inv.attestationId, secret, date: '2026-03-01' }));
```

`signer` is `{ did, sign(typ, payload) }`; the private key behind it never leaves the examiner's device. In the browser use `static/sanad-client.js` (`newAttestor`, `prepareCommit`, `prepareReveal`, same shapes, `async`).

**Seal, keep a checkpoint, hand over.**

```js
const credential = engine.finalize(a.id);
hostDb.credentials.set(pseudonym, credential);      // the holder may also keep their own copy
const cp = engine.log.checkpoint();                  // see section 7: keep every checkpoint
```

**A third party verifies (mode 3)**, with a policy of its own and the issuer and log key it has decided to trust:

```js
import { verifyCredential } from './vendor/sanad-engine.mjs';
const report = verifyCredential(credential, {
  trustedIssuers: [issuerDid], trustedLogKeys: [logKeyDid],
  policy: { minAttestors: 3, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 },
});
// report.ok            every integrity check passed (shape, issuer proof, bundle hash, signatures, log, pinned issuer)
// report.recognition   what this verifier's policy makes of the chain: status, level, confidence, explanation
```

If no `policy` is given, the template's recommendation is used and the report says so in the CLI; a serious verifier states its own. Verification needs no network and no engine instance. DIDs other than `did:key` are resolved from the DID histories embedded in the credential, or from the verifier's own resolver; a verifier that wants to rely on a history it kept earlier passes `resolver`.

## 5. The same flow as a sidecar (mode 2)

```
node bin/sanad-engine init --dir data          # writes issuer.key.json, log.key.json, operator.token (0600), store/
node bin/sanad-engine serve --dir data --port 8787
```

Operator calls carry the token; attestor calls carry only a signed statement:

```
curl -s -X POST localhost:8787/v1/templates   -H "authorization: Bearer $(cat data/operator.token)" -H 'content-type: application/json' -d @template.json
curl -s -X POST localhost:8787/v1/assessments -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d @assessment.json
curl -s -X POST localhost:8787/v1/assessments/as-1/invite -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"attestor":"did:key:z...","role":"examiner","evidence":"E1"}'
# examiner, on their own machine, with their own key file:
node bin/sanad-engine keygen --out me.key.json                                 # once; the file stays with the examiner
node bin/sanad-engine commit as-1 as-1.a01 --key me.key.json --level 4 --url http://localhost:8787
node bin/sanad-engine reveal as-1 as-1.a01 --key me.key.json --url http://localhost:8787
# operator:
curl -s -X POST localhost:8787/v1/assessments/as-1/finalize -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}'
# anyone:
curl -s -X POST localhost:8787/v1/verify -H 'content-type: application/json' -d '{"credential": {...}, "trustedIssuers": ["did:key:z..."], "policy": {...}}'
```

Rules for a sidecar:

- The server speaks plain HTTP, has no rate limiting and no user accounts. Put it behind the host's own TLS and authentication, or bind it to localhost and let only the host reach it. **Untested** behind a real reverse proxy.
- The operator token is one shared secret. Keep it on the host's server, never in a browser. Attestor routes are open by design because every body is signed; the host may still restrict who can reach them.
- Run one process per data directory (the file store is single-process). Do not run CLI operator commands while `serve` uses the same directory.
- The demonstration page at `/` is for trying things out. Turn it off with `createHttpServer({ serveStatic: false })` if the host embeds the server as a library.

## 6. Designing a template

A template says what is assessed, on what evidence, by how many attestors, and what a verifier might reasonably demand. Examples are in `engine/examples/*.template.json`.

- **Skill id.** One skill per template, with a stable id the host or a wider community uses (`analysis.limits`). Skills are not ranked and there is no registry.
- **Levels.** Always numbered 0 to 5; the labels are yours. Write each label as an observable behaviour ("solves routine problems unaided"), not as a grade or a personal quality. Optional `rubric` entries give descriptors per criterion and level.
- **Evidence plan.** Each item is `sitting` (a live, observed event), `artifact` (a thing produced; put hashes of it in the body), `auto` (a machine result; put a hash of the record in the body) or `peer`. A template that sets `liveSitting: true` needs at least one `sitting` item.
- **Attestors.** `min`, `max` and `roles`. More than two independent attestors on the key evidence item makes the lower median harder to move; one attestor is a statement, not an assessment. Roles are free text used in invitations (`examiner`, `observer`, `reviewer`).
- **Deadlines.** `commitHours` and `revealHours`. Long enough for real people in real time zones; short enough that a missing reveal is soon known. A missing or late reveal is recorded in the credential, so a stalled examiner is visible rather than silently dropped.
- **Recommended policy.** Eight fields (`minAttestors`, `requireLive`, `halfLifeMonths`, `minAttestorSittings`, `minAgreement`, `maxInferenceDepth`, `inferenceDecay`, plus an id). It is what the template author considers sensible. It travels in the credential as data. Verifiers may use it, tighten it or ignore it. Do not describe it to users as "the standard".
- **Template changes.** A template is pinned by hash: registering the same id with different content is refused (`template_exists`). Publish a new version under a new id (`maths-oral-v2`).

### Level mapping advice

Hosts often have a grading scale of their own (1 to 6, A to F, percentages). Keep that scale in the host.

1. Choose the mapping once, in writing, as part of the template (`levelMap` documents it; the engine does not apply it).
2. Convert at the edge: `claimedLevel` and each attestor's level are Sanad levels 0 to 5 by the time they reach the engine.
3. Prefer a mapping that is monotone and can be inverted for display. Do not map several distinct native grades to one level without saying so.
4. Optionally bind the native mark into the nonce (`h1-<native>-<random>`, alphabet `[A-Za-z0-9_-]`, at least 22 characters) so that the native and Sanad marks cannot drift apart after the fact.
5. Never show a Sanad level as if it were the host's grade; a level is "what these attestors observed", for the skill in the template.

## 7. What the host must keep

- **Checkpoints.** After every finalize, and on a schedule, store `engine.log.checkpoint()` (or `GET /v1/log/checkpoint`), together with the time you saw it. The log's entry chain is unkeyed; anyone who can write the store can rewrite the whole log. The rewrite is detected only by a consistency proof between a checkpoint someone kept and the current log. The toy host does this in `keepCheckpoint()` using `verifyConsistency`. Give checkpoints to others too (publish them, send them to verifiers): a checkpoint only you hold protects only you.
- **Operator keys.** Issuer key and log key, backed up, with mode 0600 on disk (the CLI sets this). Losing the issuer key means new credentials need a new issuer identity; old ones still verify against the old key a verifier pinned.
- **The engine's store**, backed up like any database: assessments, credentials, DID histories and the log stream. The log is append-only; never edit it.
- **The pseudonym to person link**, in the host's own database, under the host's own privacy rules. Without it a credential is unattributable by design.
- **DID histories** of attestors that use something other than `did:key`, if the host registers them.
- **The vendored bundle's SHA-256** and the source commit it came from (mode 1). A host test should compare the file with the recorded hash.

What the host does **not** keep: attestor private keys, nonces before reveal, names inside the engine.

## 8. Failure cases and what to do

| Situation | What happens | What the host does |
|---|---|---|
| An examiner never commits | After `commitBy` reveals open for those who committed; the one who did not is `notCommitted` | Invite a replacement only before reveals open; otherwise finalize with fewer attestors and let verifiers' `minAttestors` decide |
| An examiner commits and never reveals | After `revealBy`, finalize records `missing` and logs a `missing-reveal` leaf | Nothing; this is visible evidence. The credential may still verify but may be below a verifier's `minAttestors` |
| A reveal arrives late | `reveal_late`; recorded as late | Ask for a new sitting if needed; do not edit the record |
| A commit is replayed or copied | `already_committed` / `commit_mismatch_invitation` | Nothing |
| A reveal before everyone committed | `reveal_not_open` | Tell the examiner to wait; this protects blindness |
| Wrong key signs | `bad_signature` (HTTP 401) with a `reason` | Check the examiner uses the key matching their invited DID |
| A key was rotated or revoked | Statements dated before the revocation still verify; later ones do not | Register DID histories for non-`did:key` identities; examiners with `did:key` replace their identity instead |
| Attestor key stolen | A thief can sign statements with earlier dates; the log time of the commit is the defence | Revoke in the DID history (non-`did:key`); verifiers read log times in the report. Not fully solved |
| The log was rewritten | Consistency proof against a kept checkpoint fails | Treat the log as untrusted; restore from backup; tell verifiers |
| Credential tampered | `verify` reports failed checks; the changed attestation is dropped under R1 | Nothing; any verifier can see it |
| Template policy disagrees with a verifier | The verifier's policy wins for that verifier | Nothing; this is the design |
| Server crash between commit and the host's own record | The engine's commit is durable (file store appends with `fsync`); the host's record may lack it | Re-read the assessment (`GET /v1/assessments/:id`) as the source of truth |
| Collusion, help off camera, impersonation | Not detectable by software | Use the host's own controls (identity checks, recorded sittings, independent examiners); the credential does not claim them |

## 9. What is tested and what is not

Tested in this repository (`npx vitest run`, `node engine/vectors/run.mjs`): the library, the bundle (identical to a fresh build, no non-built-in imports), the HTTP API in-process, the CLI in-process and through the bin script, the demonstration page's static properties, the browser attestor helper against the engine in Node, the three example runs, the toy host, and the principle regressions in `engine/test/philosophy.test.mjs`.

Untested:

- Any browser: the demonstration page and `sanad-client.js` have not been run in a real browser (only the helper's logic, in Node's WebCrypto).
- Clients in other languages posting to the HTTP API, and any reverse proxy, TLS or load balancer in front of it.
- The SQLite adapter on platforms where `node:sqlite` is missing (the tests skip it), and very large logs (the in-memory tree is rebuilt on start).
- The type declarations (`index.d.ts`) have not been compiled by a TypeScript compiler; a test only checks that each declared name exists.
- Concurrent writers on one data directory (not supported).
- Real examiners, real time zones and long deadlines.
- Cryptographic review: none. No second implementation reads the same credentials yet; the engine vectors are regression vectors made by this implementation.
- Interoperability with W3C Verifiable Credentials or Open Badges tooling: the document is shaped after VC 2.0 but is not processed as JSON-LD and is not claimed to validate.

## 10. A short checklist before going live

1. Template reviewed by people who know the skill; levels written as observable behaviours.
2. Operator keys generated on the operator's machine; token and key files private.
3. Examiners create their own keys and send only their DID.
4. A clock the host trusts on the engine's machine (deadlines and key validity use it).
5. Checkpoints stored somewhere other than the engine's store, and shared.
6. A verification page or command for third parties that states the verifier's own policy.
7. A privacy notice that says what the host keeps (the link from pseudonym to person) and what the engine keeps (hashes and pseudonyms).
8. A plain statement to users that the credential records what examiners observed, that it is not accreditation, and what it cannot show.
