// Type declarations of @sanad-protocol/core 0.2.0 (algorithm sanad-0.1). Kept by hand in step with reference/src; checked by reference/src/types-dts.test.ts.
export declare const SANAD_VERSION: 'sanad-0.1';
export type Level = 0 | 1 | 2 | 3 | 4 | 5;
export type EvidenceKind = 'auto' | 'sitting' | 'artifact' | 'peer';
export interface Evidence { id: string; kind: EvidenceKind; date: string; summary: string; body: Record<string, unknown>; hash: string }
export interface Attestation {
  id: string; attestor: string; evidence: string; level: Level; role: string; conflictDeclared: boolean; date: string;
  signature: string; commit: string; nonce: string; prev: string; hash: string;
}
export interface AttestorStats { sittings: number; agreement: number }
export interface Credential { skill: string; claimedLevel: Level; subject: string; evidence: Evidence[]; attestations: Attestation[]; attestors: Record<string, AttestorStats> }
export interface Policy { minAttestors: number; requireLive: boolean; halfLifeMonths: number; minAttestorSittings: number; minAgreement: number; maxInferenceDepth: number; inferenceDecay: number; asOf: string }
export declare const DEFAULT_POLICY: Policy;
export type RuleId = 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7' | 'R8';
export interface Step { rule: RuleId; summary: string; inputs: string[]; effect: string }
export interface Dropped { id: string; rule: 'R1' | 'R2'; reason: string }
export type Status = 'not-recognised' | 'provisional' | 'recognised';
export interface Recognition {
  version: 'sanad-0.1'; skill: string; claimedLevel: Level; status: Status; level: Level; attestedLevel: Level | null; confidence: number;
  explanation: Step[]; dropped: Dropped[]; used: { evidence: string[]; attestations: string[] }; policy: Policy;
}
export interface Inferred { skill: string; level: Level; confidence: number; distance: number; path: string[]; inferred: true }

export declare function canonical(v: unknown): string;
export declare function hashOf(v: unknown): string;
export declare function sha256Hex(text: string): string;
export declare function sha256HexWebCrypto(text: string): Promise<string>;

export type EvidenceDraft = Omit<Evidence, 'hash'>;
export type AttestationDraft = { id: string; attestor: string; evidence: string; level: Level; role?: string; conflictDeclared?: boolean; date: string; nonce?: string };
export declare function sealCredential(c: { skill: string; claimedLevel: Level; subject: string; evidence: EvidenceDraft[]; attestations: AttestationDraft[]; attestors: Credential['attestors'] }): Credential;
export declare function sealEvidence(d: EvidenceDraft): Evidence;
export declare function sealAttestations(drafts: AttestationDraft[]): Attestation[];
export declare function evidenceHash(e: Pick<Evidence, 'body'>): string;
export declare function commitPayload(a: Pick<Attestation, 'attestor' | 'evidence' | 'level' | 'nonce'>): { attestor: string; evidence: string; level: Level; nonce: string };
export declare function commitOf(a: Pick<Attestation, 'attestor' | 'evidence' | 'level' | 'nonce'>): string;
export declare function attestationPayload(a: Omit<Attestation, 'hash' | 'signature'> & { signature?: string }): Omit<Attestation, 'hash' | 'signature'>;
export declare function attestationHashOf(a: Omit<Attestation, 'hash' | 'signature'> & { signature?: string }): string;

export type TamperOp = { attestation: string; set: Record<string, unknown> } | { evidence: string; set: Record<string, unknown> };
export declare function applyTamper(c: Credential, ops: TamperOp[]): Credential;

export interface Integrity { id: string; ok: boolean; reason: string }
export interface RecogniseOptions { verifySignature?: (a: Attestation) => boolean }
export declare function checkIntegrity(cred: Credential, opts?: RecogniseOptions): { evidence: Integrity[]; attestations: Integrity[] };
export declare function recognise(cred: Credential, policy: Policy, opts?: RecogniseOptions): Recognition;
export declare function dayNumber(iso: string): number;
export declare const WEIGHT: Record<EvidenceKind, number>;
export declare const CAP: Record<EvidenceKind, Level>;
export declare const QUALIFYING: readonly EvidenceKind[];
export declare const REPLAY: 'replay';

export interface SkillGraph { requires(id: string): readonly string[] }
export declare function graphFromEdges(ids: readonly string[], edges: readonly number[]): SkillGraph;
export declare function infer(graph: SkillGraph, skill: string, level: Level, confidence: number, policy: Pick<Policy, 'maxInferenceDepth' | 'inferenceDecay'>, directClaims?: Iterable<string>): Inferred[];
export declare function explainInference(skill: string, inferred: Inferred[], policy: Pick<Policy, 'maxInferenceDepth' | 'inferenceDecay'>): Step;

export declare const SAMPLE_SKILL: string;
export declare const SAMPLE_NAMES: Record<string, string>;
export declare function sampleCredential(): Credential;
export declare const SAMPLE_TAMPER: TamperOp[];
