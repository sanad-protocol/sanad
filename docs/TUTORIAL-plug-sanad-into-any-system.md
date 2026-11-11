# Plug Sanad into any system

This tutorial shows how a platform (a course site, an exam centre, a guild, a school network, a professional body) adds Sanad credentials without changing how it works today. The engine in this repository knows nothing about any platform, and no platform has a special status in the protocol: every host is one host among many. A first integration, an example host, has been built against this engine and its experience is built into this text.

Five lines to hold on to:

- Sanad is decentralised assessment of skill. It is not accreditation, and nobody vets attestors for the protocol.
- A credential is a chain of what was observed that a verifier can check and then evaluate. **Each verifier applies its own policy**; the policy inside a template is only a recommendation.
- The software is **experimental**: it has had no cryptographic review. Every verification report and the CLI say so.
- Examiners commit to a mark blind and reveal it later, so that no examiner sees another's mark before committing. The ordering is attested by the operator; the credential does not yet carry the signed commits that would let a third party check it (`docs/SPEC-DECISIONS-NEEDED.md`).
- **Attestors hold their own private keys.** The engine, the server and the library never receive or generate them.
- No names or personal data enter the engine. The protocol has no central authority, no token and no fee.

Parts of this text describe things that have been tested in this repository and parts that have not. **Tested** and **Untested** are marked in place, and section 15 lists what is untested.

Contents: 1 the three modes; 2 who holds what; 3 the flow; 4 a worked example; 5 the port and adapter pattern; 6 the browser attestor and the signing ticket; 7 level mapping; 8 subjects and pseudonyms; 9 template design; 10 deadlines; 11 what the host must keep; 12 a contract test suite; 13 what a host must not do; 14 failure cases; 15 what is tested; 16 checklist: is my integration faithful to Sanad?

## 1. The three modes

| Mode | What the host runs | Good for | Tested |
|---|---|---|---|
| 1. Library, vendored single file | `import` of `engine/dist/sanad-engine.mjs` inside the host process | Node hosts that want no extra service; one thing to deploy | Yes: toy host, port contract suite |
| 2. Sidecar HTTP service | `sanad-engine serve` beside the host; the host speaks JSON (`DESIGN.md` section 8) | Hosts in other languages; keeping operator keys out of the host process | Yes: HTTP and CLI tests, port contract suite; no test from a non-Node client |
| 3. Verify only | `verifyCredential` or `sanad-engine verify` | Employers, schools, apps that only read credentials | Yes: library and CLI tests; the same function runs in both |

Modes combine: issue with mode 2 and let third parties verify with mode 3. A host can start with mode 1 and move to mode 2 later without changing its own workflow, if it follows section 5.

For **vendoring** (mode 1): copy `engine/dist/sanad-engine.mjs` into the host, record its SHA-256 (`engine/dist/sanad-engine.mjs.sha256`) and the source commit, and add a host test that compares the file with the recorded hash. Do not take a path dependency on a checkout. Keep imports of the bundle in one module (section 5), and let a host test fail if any other file imports it: that rule makes provider swaps and upgrades small.

## 2. Who holds what

| Role | Holds | Never holds |
|---|---|---|
| **Attestor** (examiner, reviewer) | Own Ed25519 private key; the level and nonce between commit and reveal | |
| **Operator** (runs the engine) | Issuer key, log key, operator token | Any attestor private key |
| **Host** (the platform) | People, names, grades, bookings, payments; the link from a pseudonym to a person; checkpoints | Attestor private keys |
| **Verifier** (anyone) | Its own policy; the issuers and log keys it chooses to trust | |

The attestor signs in their own client: a browser page (`engine/static/sanad-client.js`), the CLI (`sanad-engine commit` and `reveal`), or the host's own app. The host forwards signed requests. It cannot sign for the attestor and must not try. A host that makes keys for attestors can forge marks, and the "attestors hold their own keys" property is gone.

## 3. The flow, whichever mode

1. The operator registers a **template** (section 9).
2. The host opens an **assessment** for a pseudonymous subject, with its evidence items.
3. The operator **invites** attestors by DID, one invitation per attestor per evidence item. An invitation can be **removed** before that attestor's first commit.
4. Each attestor **commits**: a signed hash of attestor, evidence, level and nonce. Nothing about the mark is readable.
5. When the roster is complete and every invited attestor has committed, or the commit deadline has passed, the reveal phase opens. The roster is complete when every evidence item that needs human attestors has at least `attestors.min` invitations, or when the operator has closed the invitations (`POST /v1/assessments/:id/close-invitations`); a first invitee's commit therefore cannot open the phase alone. Once open, the phase never closes. Each attestor **reveals** level and nonce, signed.
6. At any time after reveals start, anyone may ask for a **preview** of recognition over the marks revealed so far (provisional, never reading an unrevealed mark).
7. The operator **finalizes** after all reveals or after the reveal deadline. Missing and late reveals are recorded, not hidden. The engine **enforces the template**: every evidence item that needs human attestors needs at least `attestors.min` revealed attestors, and a live-sitting template needs revealed marks on sitting evidence, otherwise `below_template_minimum`. The operator can finalize anyway with `allowShortfall`, which is written into the credential (`process.shortfall`) and shown to verifiers as a warning.
8. Anyone **verifies**, with their own policy.

## 4. A worked example

`engine/examples/toy-host.mjs` is a toy course site that imports the committed bundle (mode 1); `engine/test/toy-host.test.mjs` runs it. The key parts, without the ceremony:

```js
import { createEngine, createFileStore, makeSigner, importPrivateKey, prepareCommit, prepareReveal, verifyCredential } from './vendor/sanad-engine.mjs';

// operator keys come from files with mode 0600 (sanad-engine init writes them), not from generateKeyPair() at every start
const engine = createEngine({ store: createFileStore('./sanad-data/store'), issuer, logSigner });
engine.registerTemplate(template);

const pseudonym = 'urn:uuid:' + randomUUID();                    // the host keeps the link to the person
const a = engine.createAssessment({ templateId: template.id, subject: pseudonym, claimedLevel: 3,
  evidence: [{ key: 'E1', date: '2026-03-01', summary: 'Oral sitting', body: { minutes: 40 } }] });
const inv = engine.invite(a.id, { attestor: examinerDid, role: 'examiner', evidence: 'E1' });

// on the examiner's device:
const { request, secret } = prepareCommit({ signer, ticket: await getTicket(a.id, inv.attestationId), level: 3 });
await send('/commit', request);                                    // keep `secret` on the device
// when reveals are open, still on the device:
await send('/reveal', prepareReveal({ signer, ticket, secret, date: providerDay }));

const credential = engine.finalize(a.id);
hostDb.credentials.set(pseudonym, credential);
```

In the toy host the same script plays the examiners with generated keys, which is what makes it a demonstration. Run `node engine/examples/run.mjs` for three scripted runs with different templates.

A third party verifies (mode 3) with a policy of its own and the issuer and log key it has decided to trust:

```js
const report = verifyCredential(credential, {
  trustedIssuers: [issuerDid], trustedLogKeys: [logKeyDid],        // pinned by the verifier; unpinned means ok: false
  policy: { minAttestors: 3, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8, asOf: '2026-03-02' },
  // pinnedKeys: { 'did:web:...': ['z6Mk...'] }   for did:web issuers or attestors: pin the KEY, not the name
  // attestorStats: {...}                          the verifier's own statistics, if the policy has sittings or agreement thresholds
});
// report.ok            integrity: shape, issuer proof, bundle hash, signatures, log, pinned issuer
// report.recognition   what this verifier's policy makes of the chain: status, level, confidence, explanation
```

There is **no default policy and no default evaluation day** in the library or the HTTP route: without a policy the report is `ok: false` with `recognition: null`, unless the caller passes `useRecommendedPolicy` (the issuer's recommendation, labelled in `report.basis`). The CLI refuses to verify without `--policy`, unless `--use-recommended-policy` is given, which prints that the issuer's recommendation was used. Verification needs no network and no engine instance. Three trust rules follow from keys being what is trusted, not DID names:

- **Pin the issuer and the log key.** Unpinned means `ok: false` unless `allowUnpinned`.
- **A `did:web` identity's key history inside the credential is only the issuer's claim.** The verifier pins the key (`pinnedKeys`) or supplies the history (`trustedDidHistories`); otherwise `ok` is false. Pinning a key does not pin its revocation history: a pinned key is accepted whenever the credential's history lists it as valid on the statement's date. A verifier that wants revocations to apply keeps the DID histories it trusts and passes them as `trustedDidHistories`. `did:web` registration in an engine is operator-asserted: nothing proves control of the domain.
- **Attestor statistics are the issuer's statement.** They cannot be recomputed from the log. If the policy has a sittings or agreement threshold the verifier supplies its own `attestorStats` or accepts the issuer's with `allowIssuerStatistics` (a warning).

## 5. The port and adapter pattern

**The host keeps its workflow** (accounts, bookings, rooms, payments, notifications, grades). **Exactly one module of the host talks to Sanad.** That module is a *port*: a small async interface in the host's own words. Behind it sit interchangeable *providers* (adapters): the vendored library, an HTTP sidecar, a fake for tests. Which provider runs is a configuration value.

`engine/examples/host-port.mjs` is a working port with an embedded and an HTTP provider:

```js
const sanad = createProvider({ provider: 'embedded', engine });                          // mode 1
const sanad = createProvider({ provider: 'http', url: 'http://localhost:8787', operatorToken });   // mode 2
// the host codes only against this interface, all methods async:
// info, registerTemplate, createAssessment, invite, uninvite, ticket, getAssessment, commit, reveal, preview, finalize, verify, checkpoint
```

Rules that keep the pattern honest:

1. **One import site.** Only the port module imports the bundle or calls the sidecar. A host test greps for other imports. **Tested** in the example host's practice run; the repository's own toy host follows it in `toy-host.mjs`.
2. **Same errors from every provider.** Both providers throw `{ code, status }` with the engine's codes (`already_committed`, `reveal_not_open`, `template_exists`, ...) and add `provider_unreachable` (503) for a transport failure. The host maps codes to its own messages in one place.
3. **The host's own record is a cache, the engine's record is the truth** for what was committed, revealed and finalized. After a crash, re-read the assessment (`getAssessment`) and repair the host's record from it, not the other way round. **Tested** by the example host (crash repair).
4. **A provider swap changes configuration only.** Move from embedded to HTTP by pointing the HTTP provider at the same data directory behind `serve`, after stopping the embedded process (one process per file store). **Tested** in the repository only as two providers on separate engines; migrating a live data directory is untested.
5. **Provider down is a normal state.** A sitting that cannot be sealed now is queued by the host and retried; the host never fabricates a credential and never signs for an attestor to cope with an outage.

## 6. The browser attestor and the signing ticket

Examiners usually sit in a browser. The host's page gets a **signing ticket** for one invitation (`GET /v1/assessments/:id/ticket/:attestationId`, or `engine.ticketFor` in the library). It is public data and holds no secret:

```
{ "ticketVersion": 1, "alg": "sanad-0.1", "assessment": "as-1", "attestationId": "as-1.a01", "attestor": "did:key:z...",
  "role": "examiner", "evidence": "as-1.E1", "templateHash": "<64 hex>", "levels": [0,1,2,3,4,5], "levelMap": { "g1": 0, ... },
  "commitBy": "...", "revealBy": "...", "state": "open", "revealOpen": false, "serverTime": "...", "serverDay": "2026-03-01",
  "rules": { "nonce": {...}, "date": { "format": "YYYY-MM-DD", "notBefore": "<evidence date>", "notAfter": "provider day at reveal" }, "level": "..." },
  "commit": { "typ": "sanad-commit+jws", "members": [...], "post": "/v1/assessments/as-1/commit" },
  "attestation": { "typ": "sanad-attestation+jws", "members": [...], "post": "/v1/assessments/as-1/reveal" } }
```

The client holds the key and does three things (exact bytes in `DESIGN.md` section 8a):

1. **Commit.** Choose a level, make a nonce (16 random bytes as base64url), compute `commit = SHA-256(canonical({attestor, evidence, level, nonce}))`, sign the commit statement, send `{ attestationId, payload, jws }`. Keep level and nonce on the device.
2. **Wait.** The reveal phase opens when all invited attestors have committed (or `commitBy` has passed). Poll the ticket or the assessment view.
3. **Reveal.** Sign the attestation statement with `date` taken from the **provider's** clock (`serverDay` of a fresh ticket or `/v1/info`), not the device's, so that a skewed device clock or a day boundary does not cause `bad_date`. Send `{ attestationId, statement, jws }`.

The helper `engine/static/sanad-client.js` is the model of a browser client: no dependency, WebCrypto Ed25519, `newAttestor`, `prepareCommit`, `prepareReveal`, all accepting a ticket. A host may reimplement the same contract in any language; the engine vectors and `test/client.test.mjs` pin the bytes. A host page should show the examiner what is being signed, keep the key in memory or in the platform's key store, and never post it. **Tested:** the helper's logic runs in Node's WebCrypto against the engine; the example host additionally drove it in a real browser. **Untested here:** any browser in this repository's own tests.

Two more calls help a host's interface, neither changes any mark:

- **Preview** (`POST /v1/assessments/:id/preview`, `{ policy? }`): recognition over the attestations revealed so far, always labelled provisional, under the verifier's policy if supplied, otherwise under the template's labelled recommendation. It never reads an unrevealed mark; it reports only how many are pending. Use it for a progress screen, never as a result.
- **Removing an invitation** (operator, `POST /v1/assessments/:id/invitations/:att/remove`): only before that attestor's first commit. The attestation id is never reused, the removal is recorded in the events stream and, at finalize, under `process.removed` in the credential. Use it for an examiner who falls ill before the sitting, not to drop an examiner whose commit is unwelcome (that is refused).

## 7. Level mapping

Sanad levels are 0 to 5. A host often has its own scale (1 to 6, A to F, percentages). Keep the host's scale in the host.

1. Decide the mapping once, in writing, as part of the template. The template's optional `levelMap` records it: host-native label (1 to 16 letters or digits, for example `g1` to `g6`) to Sanad level.
2. Convert at the edge. Claimed level and each attestor's level are Sanad levels by the time they reach the engine.
3. To **preserve the native mark** in the credential without weakening the blind commit, let the attestor's client write it into the nonce: `nm-<native>-<random>` (the `native` option of `prepareCommit`). The nonce is part of the commit hash and is revealed only at the reveal, so nothing about the native mark is visible earlier. At the reveal the engine checks that the native mark is in the `levelMap` and maps to the revealed level. Never send a native mark beside the commit: that would weaken blindness.
4. Prefer a monotone mapping that can be inverted for display. Do not collapse several native grades into one level without saying so.
5. Never show a Sanad level as the host's grade. A level is what these attestors observed for the skill in the template.

## 8. Subjects and pseudonyms

The engine accepts only `urn:uuid:<RFC 4122 UUID, lower case>` or `urn:sanad:subject:<32 to 64 lower-case hex characters>` as a subject, so that a name or an e-mail address cannot be typed in by mistake. This is a **guard rail**, not proof of pseudonymity: the host must generate the value without using personal data (a random UUID, or a keyed hash with a key that stays in the host). The host keeps the link from the pseudonym to the person, under its own privacy rules. Without that link a credential is unattributable by design; with it, the host decides who may see it. Evidence `summary` and `body`, the assessment id and every other free-text field end up in the public credential and the engine's store: they must not hold names, addresses or other personal data either. Credentials, the log and the engine's store then hold pseudonyms, DIDs and hashes only. **Tested:** the engine refuses names; the toy host test checks that the credential holds no name.

## 9. Template design

Examples: `engine/examples/*.template.json`.

- **Skill id.** One skill per template, with a stable id the host or a wider community uses. There is no registry and no ranking.
- **Levels.** Always 0 to 5; the labels are yours. Write each as an observable behaviour ("solves routine problems unaided"), not a personal quality.
- **Evidence plan.** `sitting` (a live, observed event), `artifact` (put hashes in the body), `auto` (a machine result, a hash of the record in the body), `peer`. A template with `liveSitting: true` needs at least one `sitting` item.
- **Attestors.** `min`, `max`, `roles`. One attestor is a statement, not an assessment; more than two independent attestors on the key evidence make the lower median harder to move.
- **Deadlines.** `commitHours` and `revealHours` (section 10).
- **Recommended policy.** Seven policy fields and an id. It is what the template author considers sensible, it travels in the credential as data, and verifiers may use it, tighten it or ignore it. Do not describe it to users as "the standard".
- **Versions.** A template is pinned by hash; the same id with different content is refused (`template_exists`). Publish changes as a new id.

## 10. Deadlines: host policy and engine records

The engine **enforces** two deadlines per assessment, `commitBy` and `revealBy`, set at creation from the template's hours or explicitly. After `commitBy` a commit is refused (`commit_closed`); after `revealBy` a reveal is refused and recorded as late (`reveal_late`); finalize is allowed once everyone has revealed or `revealBy` has passed. The engine has **no operation to extend a deadline**.

The host's **policy** is everything around that: reminders, grace periods, whether to reschedule a sitting, whether to open a new assessment. Rules of thumb:

- Set engine deadlines **generously** at creation and enforce any stricter, humane limits in the host's workflow (reminders, a "please reveal by" date shown to examiners). A deadline that is too short cannot be lengthened later; a new assessment is the only remedy.
- Make the engine record what happened (missing, late) and let verifiers weigh it; do not hide a missing reveal by finalizing with fewer examiners and hoping.
- Use the provider's clock (`info().time`) for anything that must agree with the engine: reveal dates, countdowns, "reveals open" screens.

## 11. What the host must keep

- **Backups of the issuer key and the log key.** Both live in files with mode 0600 (`sanad-engine init`) or in the operator's own secret store, backed up where the host backs up secrets. Losing the issuer key means new credentials need a new issuer identity (old ones still verify against the key a verifier pinned). Losing the log key means a new log. Never keep them in the repository or in the host's database next to ordinary data. **Untested:** restoring from backup on a fresh machine.
- **Checkpoints.** After every finalize, and on a schedule, store `engine.log.checkpoint()` (or `GET /v1/log/checkpoint`) with the time seen, in a place other than the engine's store, and check each new one against the last with a consistency proof (`engine.log.consistency` and `verifyConsistency`; `toy-host.mjs` does this in `keepCheckpoint()`). The log's entry chain is unkeyed; anyone who can write the store can rewrite the whole log, and only a checkpoint someone kept reveals it. Give checkpoints to others too: one that only you hold protects only you.
- **The engine's store**, backed up like any database. The log is append-only; never edit it.
- **The link from pseudonym to person**, in the host's database.
- **DID histories** of attestors that use something other than `did:key`.
- **The vendored bundle's SHA-256** and the source commit it came from.

What the host does **not** keep: attestor private keys, nonces before reveal, names inside the engine.

## 12. A contract test suite

A host that follows section 5 can test its port against any provider with one suite. The repository has the model: `engine/test/port-contract.test.mjs` runs the same scenario on the embedded and the HTTP provider and checks exactly what a host relies on:

- the response body of each call (template registration returns `{ id, hash }` and returns the same pair again for identical content; finalize returns the credential; commit returns `{ committed, of }`; verify returns the report);
- the error codes and statuses of refusals (`already_committed`, `reveal_not_open`, `not_ready`, `not_invited`, `template_exists`, `unauthorized`, `provider_unreachable`);
- the blind-commit properties (no reveal before everyone committed; no mark or nonce in any pre-reveal response; the preview never contains an unrevealed nonce);
- credentials from either provider verify in verify-only mode with no provider.

A third provider, whether a different transport or a second implementation of the protocol, is faithful to what the host needs if it passes the same suite. Add a **vendor test** (hash of the bundle equals the recorded one, only the port imports it) and a **browser parity test** (the page's signing code yields the same bytes as the Node helper for the same inputs). **Untested:** the suite against anything but this engine.

## 13. What a host must not do

- **Vet attestors on behalf of the protocol.** A host may decide whom *it* invites, for its own reasons, and say so. It must not present its list as something Sanad requires or certifies. Nobody vets attestors for the protocol; verifiers weigh attestors through their own policies.
- **Claim accreditation.** A Sanad credential is a recomputable chain of what was observed. It is not accreditation, licensure or an endorsement by the protocol. Do not write "accredited by Sanad", "Sanad certified" or similar, and do not seek accreditation for Sanad.
- **Store, generate or ask for attestor private keys**, even "for convenience", even encrypted, even in a log. The only things that cross to the engine are signed statements.
- **Put names or contact details in the engine**, in a subject URN, an evidence summary or a body.
- **Hide missing or late reveals**, or finalize in a way that hides who did not reveal.
- **Treat the template's policy as the answer.** Show the verifier's own result or show the recommendation labelled as one.
- **Add a fee, a token or a central authority to the protocol path.** A host may charge for its own services; that is outside Sanad and must not be presented as part of it.
- **Edit the log or a credential** after issue. Corrections are new assessments.
- **Promise what software cannot show**: collusion, help off camera and identity checks are outside what any chain proves. The host's own controls handle them and the host says so.

## 14. Failure cases

| Situation | What happens | What the host does |
|---|---|---|
| An examiner never commits | After `commitBy`, reveals open for those who committed; the missing one is `notCommitted` | Remove the invitation before the first commit if known earlier; if the template minimum is then not met, finalize refuses (`below_template_minimum`): open a new assessment, or finalize with `allowShortfall` knowing that verifiers will see the shortfall |
| An examiner commits and never reveals | After `revealBy`, finalize records `missing` and a `missing-reveal` log leaf | Nothing; this is visible evidence |
| A reveal is late | `reveal_late`, recorded as late | A new assessment if needed; no edits |
| A commit is copied or replayed | `commit_mismatch_invitation`, `already_committed` | Nothing |
| A reveal before everyone committed, or before the roster is complete | `reveal_not_open` | Tell the examiner to wait, or close the invitations if the roster is final; this protects blindness |
| Wrong key signs | `bad_signature` (401) with `reason` | Check the examiner uses the key behind the invited DID |
| Wrong date on a reveal | `bad_date` | Use the provider's day, not the device's |
| Native mark disagrees with the level | `native_mismatch` at the reveal | The client library maps native marks; do not hand-write nonces |
| Remove after commit | `already_committed` | Not possible by design |
| A key was rotated or revoked | Statements dated before the revocation still verify, later ones do not | Register DID histories for non-`did:key` identities; `did:key` holders replace their identity |
| Attestor key stolen | A thief can sign statements with earlier dates, and **no verifier detects this**: the key is checked against the date the statement itself carries | Revoke in the DID history for future statements; keep the signed commits and checkpoints; verifiers who pin a verifier-held DID history (`trustedDidHistories`) at least see revocations they know about. Not solved |
| The log was rewritten | The consistency proof against a kept checkpoint fails | Treat the log as untrusted; restore from backup; tell verifiers |
| The provider is down | `provider_unreachable` | Queue and retry; never fabricate or sign locally |
| The operator's clock steps back | The engine's clock never runs backwards; a commit is refused once any reveal exists | Nothing; fix the clock for future deadlines |
| Finalize crashes half way | A retry appends no duplicate log leaves and overwrites the same credential id | Call `finalize` again |
| Crash between the engine call and the host's own record | The engine's record is durable (the file store appends with `fsync`) | Re-read the assessment and repair the host's record |
| Credential tampered | `verify` lists failed checks; changed attestations are dropped under rule R1. A forged credential under the forger's own keys passes every integrity check; only a verifier that **pinned** the issuer and log key (and, for `did:web`, the keys) refuses it | Tell verifiers to pin; nothing else can be done in the document |
| Template policy disagrees with a verifier | The verifier's policy wins for that verifier | Nothing; this is the design |
| Collusion, help off camera, impersonation | Not detectable by software | Use the host's own controls and say so |

## 15. What is tested and what is not

Tested in this repository (`npx vitest run`, `node engine/vectors/run.mjs`): the library, the bundle (identical to a fresh build, no imports other than built-ins), the HTTP API in process, the CLI in process and through its script, the page's static properties, the browser attestor helper against the engine in Node, the three example runs, the toy host, two independent cross-checkers in Python and Ruby (pinned issuer and log key required, shared-log credentials, a pinned explanation of their confidence agreement with the engine; see `engine/test/crosscheck/README.md`), the port contract suite on the embedded and HTTP providers, nine deterministic vectors, and the principle regressions (`engine/test/philosophy.test.mjs`).

Untested:

- Any browser in this repository's tests (the example host ran the helper in a real browser; that run is not part of this repository).
- Clients in other languages, and any reverse proxy, TLS terminator or load balancer in front of the HTTP API.
- Migrating a live data directory from embedded to sidecar, restoring from backup, concurrent writers (one process per data directory is required).
- The SQLite adapter where `node:sqlite` is missing (tests skip it) and very large logs (the Merkle tree is rebuilt on start).
- The type declarations (`engine/index.d.ts`) have not been compiled by a TypeScript compiler; a test checks only that each declared name exists.
- Real examiners over long deadlines and several time zones.
- Cryptographic review: none. No second implementation reads the same credentials yet; the engine vectors are regression vectors produced by this implementation.
- Interoperability with W3C Verifiable Credentials or Open Badges tooling: the document is shaped after VC 2.0 but is not processed as JSON-LD and is not claimed to validate.

## 16. Checklist: is my integration faithful to Sanad?

Tick each box; a "no" is a defect in the integration, not a detail.

**Keys and identity**
- [ ] Every attestor key is made and kept by the attestor; no host code path can sign for an attestor.
- [ ] Issuer and log keys are in files with mode 0600 or a secret store, and are backed up.
- [ ] No name, e-mail address or contact detail is in any subject, evidence summary or body; subjects are URNs.

**Blindness**
- [ ] Commits are sent before any mark is shown to any examiner; reveals only when the engine opens them.
- [ ] No mark or nonce is shown anywhere in the host before the reveal (including logs, analytics and error messages).
- [ ] Native marks, if kept, travel only inside the nonce.
- [ ] Previews are labelled provisional and are never presented as results.

**Verification and policy**
- [ ] The host's pages show the verifier's own policy result, or the template recommendation labelled as a recommendation.
- [ ] The host's verification pins the issuer and log key, and for `did:web` the keys; it supplies its own attestor statistics if a threshold uses them.
- [ ] The host says that commit-before-reveal ordering is attested by the operator, and keeps the signed commits and checkpoints so that others can check it.
- [ ] Third parties can verify without calling the host (the credential is portable; they pin issuer and log key themselves).
- [ ] Missing and late reveals and removed invitations are visible in what the host shows.

**No authority**
- [ ] The host does not present its invitation list as vetting by Sanad, and does not use the word accreditation for the credential.
- [ ] No fee, token or gatekeeper has been placed inside the protocol path.

**Operations**
- [ ] One module talks to Sanad; a test fails if another file imports the bundle or calls the sidecar.
- [ ] A contract suite runs against every provider in use.
- [ ] The vendored bundle's hash is checked by a host test.
- [ ] Checkpoints are stored outside the engine's store, compared by consistency proofs, and shared.
- [ ] The host reads the provider's time for reveal dates and countdowns.
- [ ] The host repairs its own records from the engine's after a crash.

**Honesty**
- [ ] Users are told that the credential records what examiners observed, that it is not accreditation, and what it cannot show (collusion, help off camera, identity).
- [ ] The host says plainly that the engine has had no external cryptographic review.
