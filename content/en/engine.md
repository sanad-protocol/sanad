---
key: engine
lang: en
path: /engine/
nav: engine
title: The Sanad engine
description: The Sanad engine runs one assessment end to end and issues credentials that any verifier can recompute. Version 0.2.0.
toc: true
---

<!-- glance -->
- A small program that runs an assessment from template to sealed credential, with blind commits, a transparency log and verification under the verifier's own policy.
- Implements algorithm `sanad-0.1` of SANAD-SPEC-0.1 unchanged. Package version 0.2.0. No runtime dependencies; Node 22 or later.
- Attestors keep their own keys. No external cryptographic review and no independent implementation yet.
<!-- /glance -->

## What the engine is

The engine runs one assessment from start to finish. It holds an assessment template, invites attestors by their DID, accepts blind commits and then the reveals, builds the evidence chain, seals a credential with the core library, signs it with the issuer key and appends hashes to a transparency log. Anyone can then verify the credential: the issuer proof, the bundle hash, the attestor signatures and the log inclusion, followed by the recognition function under the verifier's own policy. The policy recommended by the template is only a recommendation.

The engine is available as a library, an HTTP API (`node:http`), a command-line tool and a small demonstration page.

## What it does not do

- It does not vet attestors. Nobody vets them for the protocol (specification section 9).
- It does not run a live room, video or proctoring, and it takes no payments.
- It does not fetch DID documents over the network, publish skill cards or run an index.
- It does not implement selective disclosure (SD-JWT) or a Bitstring Status List, and it does not anchor checkpoints with OpenTimestamps.
- It does not rank people.
- It is not accreditation and claims nothing about the honesty of a sitting: a chain says what was observed.

## Relation to the specification

The engine implements algorithm `sanad-0.1` of [SANAD-SPEC-0.1](/spec/0.1/) and does not change it. The specification stays at version 0.1; the code is at version 0.2.0. Where the specification text and the reference code differ, the engine follows the reference code and the 20 conformance vectors. The differences are listed under [open points](#open-points).

## The parts

| Part | Role |
|---|---|
| `reference/` (`@sanad-protocol/core` 0.2.0) | Canonical JSON, SHA-256, sealing helpers, rules R1 to R8, the 20 conformance vectors, and the `sanad` command (`verify`, `run-vectors`). |
| `engine/` (`@sanad-protocol/engine` 0.2.0) | Plain ES modules; `dist/sanad-engine.mjs` is a single-file bundle of core and engine for vendoring. |
| Keys | Ed25519 keys, `did:key`, detached JWS, DID document histories with rotation and revocation. |
| Templates | Template schema and validator; the template hash is pinned. |
| Commit and reveal | Blind commits, reveals, deadlines, late and missing reveals, independence checks. |
| Evidence chain and credential | Sealing, bundle hash, issuer proof, credential verification. |
| Transparency log | Merkle tree (RFC 9162) with inclusion and consistency proofs and signed checkpoints. |
| Attestor statistics | Sittings and agreement, derived from finalized assessments. |
| Storage | Memory, file (JSON files and JSON lines) and SQLite adapters. |
| HTTP API and demonstration page | JSON over `node:http`; strict content security policy, no external code. |
| CLI | `sanad-engine`. |
| Examples | Three templates with scripted runs in `engine/examples/`. |
| Engine vectors | Deterministic vectors in `engine/vectors/`. |

## Quickstart

```
git clone https://github.com/sanad-protocol/sanad.git
cd sanad
npm ci
node engine/bin/sanad-engine init
node engine/bin/sanad-engine serve
```

`init` writes the issuer key and the log key to files with mode 0600 and creates the data directory. `serve` starts the HTTP API and the demonstration page.

## A scripted example

```
node engine/examples/run-all.mjs
```

The script runs three example assessments from template to verified credential: a mathematics oral examination, a practical craft test and a language speaking test. It uses a separate demonstration helper that generates attestor keys so that one script can play several attestors.

## Command line

| Command | Purpose |
|---|---|
| `sanad-engine init [--dir]` | Create keys and the data directory. |
| `sanad-engine keygen --out <file>` | Make a demonstration attestor key. |
| `sanad-engine template add <file>` | Register a template. |
| `sanad-engine create-assessment --template <id> --subject <id> --level <n>` | Create an assessment; options `--evidence <file>`, `--commit-by`, `--reveal-by`. |
| `sanad-engine invite <assessment> --attestor <did> --evidence <id>` | Invite an attestor; option `--role`. |
| `sanad-engine commit <assessment> <attestationId> --key <file> --level <n>` | Blind commit; the nonce is kept in a local file next to the key. |
| `sanad-engine reveal <assessment> <attestationId> --key <file>` | Reveal. |
| `sanad-engine finalize <assessment> [--out]` | Seal and issue the credential. |
| `sanad-engine verify <credential.json> [--policy <file>]` | Verify a credential. |
| `sanad-engine log checkpoint`, `inclusion`, `consistency` | Read the transparency log. |
| `sanad-engine serve [--port] [--host]` | Start the HTTP server. |

The core command `sanad` offers `verify` (recognition only, without signature checks, and it says so) and `run-vectors [file]`.

## HTTP API

JSON over `node:http`; the body limit is 256 KiB and `content-type: application/json` is required on POST. Operator routes need `authorization: Bearer <operator token>`. Attestor routes are open because the body is signed. Errors have the form `{ "error": code, "message": text }`.

| Method and path | Who | Purpose |
|---|---|---|
| `GET /healthz` | anyone | Liveness. |
| `GET /v1/info` | anyone | Engine version, algorithm, issuer DID, log id. |
| `POST /v1/templates`, `GET /v1/templates`, `GET /v1/templates/:id` | operator, anyone | Register and read templates. |
| `POST /v1/dids`, `GET /v1/dids/:did` | operator, anyone | Register a DID document history or a signed update. |
| `POST /v1/assessments`, `GET /v1/assessments/:id` | operator, anyone | Create; public view (no nonces before reveal). |
| `POST /v1/assessments/:id/invite` | operator | Invite an attestor. |
| `POST /v1/assessments/:id/commit` | attestor (signed) | Blind commit. |
| `POST /v1/assessments/:id/reveal` | attestor (signed) | Reveal. |
| `POST /v1/assessments/:id/finalize` | operator | Seal and issue the credential. |
| `GET /v1/credentials/:id` | anyone | The credential. |
| `POST /v1/verify` | anyone | Verification report for a posted credential and optional policy. |
| `GET /v1/log/checkpoint`, `/v1/log/entries`, `/v1/log/inclusion`, `/v1/log/consistency` | anyone | The transparency log. |
| `GET /v1/attestors/:did/stats` | anyone | Derived statistics. |
| `GET /` | anyone | The demonstration page. |

## Keys

Ed25519 throughout (RFC 8032, `node:crypto`). Attestors hold their own private keys. The engine, its HTTP server and its library entry never receive, store or generate an attestor's private key; they receive signed statements only. The issuer key and the log key belong to the operator who runs the engine. The demonstration helper that generates attestor keys is a separate file and is never imported by the engine core, the HTTP server or the library entry.

A `did:key` cannot rotate; a lost or compromised `did:key` is replaced by a new identity. Other DIDs are registered with the engine as a document history, and every later version must be signed by a key valid in the previous version.

## Security notes

- Every signed payload names the assessment, the attestation id and its signature type, and a commit is accepted once, so a statement cannot be replayed for another purpose.
- Member sets are closed, JSON is canonical, and the bundle hash covers complete objects, so a sealed bundle cannot be altered without changing the hash.
- Secrets such as the operator token are compared in constant time. Commits are public values.
- Backdating with a stolen key is not fully solved: a revoked key can still sign statements with an earlier date. The log time of the commit is the defence, and the verifier report shows it.
- Collusion, help off camera and identity checks are outside what any software can prove.

## What is not claimed

- The engine has had no external cryptographic review.
- No independent implementation checks its outputs.
- The Ed25519 and SHA-256 primitives are those of Node.
- There are no attestors outside the steward's circle yet.
- It is not a blockchain, has no token, and is not accreditation.

## Open points

The design document lists ten places where the specification text and the reference code differ or leave a question open. The specification is not edited; the engine follows the reference code and the vectors. In summary: the form of the commit hash; field names in attestations and evidence; what the evidence hash covers; the length of a month; what an attestor signature covers; how a failed signature is treated under R1; the definition of the bundle hash; which median the agreement statistic uses; how a credential is secured; and which events are logged. Read the full list in the [design document](https://github.com/sanad-protocol/sanad/blob/main/engine/DESIGN.md).

## Conformance statement

The Sanad engine 0.2.0 implements the Verifier, Issuer, Attestor (client helper) and Log conformance classes of SANAD-SPEC-0.1 as far as the public vectors test them: it passes the 20 conformance vectors of the specification and the engine vectors in `engine/vectors/`. This statement is made by the steward; it has not been checked by an independent party.

See also [Conformance](/conformance/) and [For implementers](/for/implementers/).
