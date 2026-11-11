# Sanad engine (`@sanad-protocol/engine` 0.2.0)

A small program that runs assessments end to end and produces Sanad credentials that anyone can recompute. It implements algorithm `sanad-0.1` of SANAD-SPEC-0.1 without changing it. No runtime dependencies; Node 22 or later.

Sanad is decentralised assessment of skill. It is not accreditation. Nobody vets attestors for the protocol. A credential is a recomputable chain of what was observed, and each verifier applies its own policy: the policy that a template carries is a recommendation only. The protocol has no central authority, no token and no fee, and it gives no implementer a special status: any platform is one host among many.

## What the engine does

- Holds assessment **templates** (skill, levels, rubric, evidence plan, attestor requirements, a recommended verifier policy).
- Runs **one assessment**: create it, invite attestors by DID, take **blind commits**, then **reveals**, enforce deadlines, record missing and late reveals. Blind means that an examiner commits to a mark (hash of level and a secret nonce) before any examiner can see another's mark, so marks cannot be copied.
- Seals a **credential** (evidence chain, attestation chain, bundle hash, issuer proof), appends hashes to a **transparency log** (RFC 9162 Merkle tree with signed checkpoints), and **verifies** any credential: signatures, hashes, log inclusion, then recognition under the verifier's own policy.
- Offers this as a library, an HTTP API, a CLI and a demonstration page.

## What the engine does not do

It does not vet attestors, run a live room or proctoring, take payments, fetch DID documents over a network, or rank people. It never receives, stores or generates an attestor's private key: attestors sign on their own device and send only signed statements. No names or personal data enter the engine: subjects are pseudonymous URNs (a host keeps the link to a real person), and the log holds only hashes.

## Limits, stated plainly

The engine has had no external cryptographic review and no independent implementation checks its output; Ed25519 and SHA-256 are Node's. Collusion between examiners, help off camera and identity checks cannot be proved by any software: a chain says what was observed, not that the observers were honest. The integration tutorial marks which parts are untested. See `DESIGN.md` section 11 and section 14.

## Use it

Three ways to plug it into a system (details and a worked example in [`../docs/TUTORIAL-plug-sanad-into-any-system.md`](../docs/TUTORIAL-plug-sanad-into-any-system.md)):

1. **Library, vendored.** Copy `dist/sanad-engine.mjs` (one file, no dependencies) into the host, record its SHA-256 (`dist/sanad-engine.mjs.sha256`) and the source commit, and `import { createEngine } from './vendor/sanad-engine.mjs'`.
2. **Sidecar HTTP service.** `node bin/sanad-engine init --dir data && node bin/sanad-engine serve --dir data`. The host talks JSON to it (`DESIGN.md` section 8).
3. **Verify only.** `import { verifyCredential } from ...` or `node bin/sanad-engine verify credential.json --issuer <did> --log-key <did> --policy policy.json`. Needs no engine instance, no data directory and no network.

```
npm ci                          # in the repository root: only for tests and the bundle build
npx vitest run                  # all tests
node engine/examples/run.mjs    # three scripted end-to-end runs
node engine/vectors/run.mjs     # deterministic engine vectors
node engine/build.mjs           # rebuild dist/sanad-engine.mjs and print its SHA-256
node engine/bin/sanad-engine help
```

## Files

| Path | Role |
|---|---|
| `src/` | The engine (plain ES modules; no build step to run) |
| `dist/sanad-engine.mjs`, `.sha256` | Single-file bundle for vendoring (built by `build.mjs`, committed, checked by a test) |
| `index.d.ts` | Type declarations |
| `static/` | Demonstration page (strict CSP, no external code; the attestor key is made and kept in the page) |
| `examples/` | Three templates with scripted runs, and a toy host |
| `vectors/` | Deterministic `engine-*.json` vectors |
| `../docs/TUTORIAL-plug-sanad-into-any-system.md` | How to plug Sanad into any system |
| `examples/host-port.mjs` | The port/adapter module a host writes (embedded or HTTP provider chosen by configuration) |
| `DESIGN.md` | Design, formats, security considerations, open points |

The core recognition function and its 20 conformance vectors live in `../reference/`.

## HTTP API in one screen

Operator routes (`POST` of templates, DIDs, assessments, invitations, finalize; `GET /v1/assessments`) need `authorization: Bearer <token>`. Reads, verification and the attestor routes (`commit`, `reveal`, whose bodies are signed) are open. Body limit 256 KiB; JSON only; errors are `{ "error": code, "message": text }`. Full table in `DESIGN.md` section 8. Run it on localhost or behind the host's own authentication and TLS: the server speaks plain HTTP and has no rate limiting.
