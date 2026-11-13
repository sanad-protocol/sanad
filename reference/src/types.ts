// Sanad v0.1: the data the recognition function reads and the answer it gives.
// Everything here is plain data (JSON). The function is pure and deterministic: the same input always gives the same answer, so anyone can recompute it.
export const SANAD_VERSION = 'sanad-0.1';

/** 0 none, 1 aware, 2 guided, 3 independent, 4 fluent and transfers, 5 expert. */
export type Level = 0 | 1 | 2 | 3 | 4 | 5;
export type EvidenceKind = 'auto' | 'sitting' | 'artifact' | 'peer';

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  /** Day the evidence was produced, ISO yyyy-mm-dd. */
  date: string;
  /** Human-readable one-liner (not hashed). */
  summary: string;
  /** The hashed payload. For kind 'auto' it must contain `autoLevel` (the level a replay of the seeded exercises yields). */
  body: Record<string, unknown>;
  /** sha256 hex of canonical(body). */
  hash: string;
}

export interface Attestation {
  id: string;
  /** Attestor DID, e.g. did:sanad:ember. */
  attestor: string;
  /** Id of the evidence item attested. */
  evidence: string;
  level: Level;
  role: string;
  conflictDeclared: boolean;
  date: string;
  /** The attestor's signature. The conformance vectors use a placeholder ("unsigned-v0.1:" + hash); the engine stores a detached JWS (EdDSA, typ sanad-attestation+jws) over the attestation without prev, hash and signature. */
  signature: string;
  /** Blind marking: commit = sha256(canonical({attestor, evidence, level, nonce})), published before the reveal. */
  commit: string;
  nonce: string;
  /** Hash of the previous attestation in id order ("GENESIS" for the first): a simple chain. */
  prev: string;
  /** sha256 of canonical(all fields above except hash and signature). */
  hash: string;
}

export interface AttestorStats { sittings: number; agreement: number }

export interface Credential {
  skill: string;
  claimedLevel: Level;
  subject: string;
  evidence: Evidence[];
  attestations: Attestation[];
  attestors: Record<string, AttestorStats>;
}

/** Chosen by the VERIFIER, not by the issuer. */
export interface Policy {
  minAttestors: number;
  requireLive: boolean;
  halfLifeMonths: number;
  minAttestorSittings: number;
  minAgreement: number;
  maxInferenceDepth: number;
  inferenceDecay: number;
  /** The day the recognition is evaluated for, ISO yyyy-mm-dd (never the clock). */
  asOf: string;
}
export const DEFAULT_POLICY: Policy = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 3, minAgreement: 0.6, maxInferenceDepth: 2, inferenceDecay: 0.7, asOf: '2026-11-07' };

export type RuleId = 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7' | 'R8';
export interface Step { rule: RuleId; summary: string; inputs: string[]; effect: string }
export interface Dropped { id: string; rule: 'R1' | 'R2'; reason: string }
export type Status = 'not-recognised' | 'provisional' | 'recognised';

export interface Recognition {
  version: typeof SANAD_VERSION;
  skill: string;
  claimedLevel: Level;
  status: Status;
  /** The level the function gives. */
  level: Level;
  /** What R6 would give if R5 were met (null when there is no qualifying evidence). Informational. */
  attestedLevel: Level | null;
  confidence: number;
  explanation: Step[];
  dropped: Dropped[];
  used: { evidence: string[]; attestations: string[] };
  policy: Policy;
}

export interface Inferred {
  skill: string;
  level: Level;
  confidence: number;
  distance: number;
  /** From the recognised skill down to this one, ids in order (the recognised skill first). */
  path: string[];
  inferred: true;
}
