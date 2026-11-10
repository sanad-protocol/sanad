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
- HTTP API, command-line tool `sanad-engine` and a demonstration page.
- Three example assessments (mathematics oral examination, practical craft test, language speaking test).
- Engine vectors in `engine/vectors/`.

### Website

- Engine page in English and German.
- Status page updated.

## 0.1.0 (7 November 2026)

Specification SANAD-SPEC-0.1, reference implementation, 20 conformance vectors, website.
