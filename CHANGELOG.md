# Changelog

## 0.2.0 (unreleased)

### Core (`@sanad-protocol/core` 0.2.0)

- Exports map and type declarations.
- New `sanad` command with `verify` and `run-vectors`.
- Optional signature check in rule R1; without it the behaviour is as in 0.1.
- Algorithm `sanad-0.1` unchanged; the 20 conformance vectors unchanged.

### Engine (`@sanad-protocol/engine` 0.2.0)

- Keys: Ed25519, `did:key`, detached JWS, DID document histories with rotation and revocation.
- Assessment templates with schema and validator.
- Blind commit and reveal, deadlines, late and missing reveals, independence checks.
- Evidence chain, credential sealing, issuer proof and credential verification.
- Transparency log (RFC 9162) with inclusion and consistency proofs and signed checkpoints.
- Attestor statistics.
- Storage adapters: memory, file, SQLite.
- Single-file bundle `dist/sanad-engine.mjs` with recorded SHA-256; type declarations.
- Integration tutorial (library, sidecar, verify-only); principle-regression tests.
- Subjects must be pseudonymous URNs (`bad_subject` otherwise).
- Signing ticket for browser attestors (`GET /v1/assessments/:id/ticket/:att`, `engine.ticketFor`); helpers accept a ticket.
- `levelMap` defined: host-native mark to level, carried in the nonce (`nm-<native>-<random>`), checked at the reveal; blind commit unchanged. Keys restricted to letters and digits.
- Provider time in `info()` (`time`, `today`).
- Recognition preview over revealed attestations only (`POST /v1/assessments/:id/preview`).
- Invitation removal before the first commit (`process.removed` in the credential when used).
- HTTP request and response bodies documented in full; port and adapter example and contract suite; three more engine vectors.
- Public tutorial `docs/TUTORIAL-plug-sanad-into-any-system.md`.
- Review round: verifier pins keys (embedded `did:web` histories untrusted by default), explicit verifier policy and day, all policy fields validated, verifier statistics and allow-list, duplicate marks dropped, id and role checks, monotonic phases and clock, template minimum enforced at finalize (`allowShortfall` override recorded), idempotent finalize, bounded and I-JSON-checked HTTP input, non-extractable browser key, complete `index.d.ts`, experimental notice in every report, independent Python cross-check, `docs/SPEC-DECISIONS-NEEDED.md`.
- HTTP API, command-line tool `sanad-engine` and a demonstration page.
- Three example assessments (mathematics oral examination, software testing portfolio, practical welding test) and a toy host.
- Six deterministic engine vectors in `engine/vectors/`.

### Website

- Engine page in English and German.
- Status page updated.

## 0.1.0 (7 November 2026)

Specification SANAD-SPEC-0.1, reference implementation, 20 conformance vectors, website.
