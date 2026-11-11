// Type declarations for @sanad-protocol/engine 0.2.0 (algorithm sanad-0.1). Experimental: not cryptographically reviewed.
// The core recognition types live in @sanad-protocol/core. A test fails if a runtime export of src/index.mjs is not declared here.
import type { Server } from 'node:http';
import type * as Core from '@sanad-protocol/core';

export type Level = 0 | 1 | 2 | 3 | 4 | 5;
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export class EngineError extends Error { code: string; status: number; reason?: string; constructor(code: string, message?: string, status?: number); }
export function fail(code: string, message?: string, status?: number): never;

// ---- keys, signatures, DIDs
export interface Signer { did: string; kid: string; publicKey: Uint8Array; sign(typ: string, payload: unknown): string; }
export interface Clock { now(): number; }
export function b64u(bytes: Uint8Array): string;
export function fromB64u(s: string): Uint8Array;
export function base58btcEncode(bytes: Uint8Array): string;
export function base58btcDecode(s: string): Uint8Array;
export function generateKeyPair(): any;
export function keyPairFromSeed(seed: Uint8Array): any;
export function publicKeyOf(privateKey: unknown): Uint8Array;
export function makeSigner(privateKey: unknown, did?: string): Signer;
export function exportPrivateKey(privateKey: unknown): string;
export function importPrivateKey(s: string): any;
export function isSmallOrderKey(raw32: Uint8Array): boolean;
export function didKeyFromPublicKey(raw32: Uint8Array): string;
export function publicKeyFromDidKey(did: string): Uint8Array;
export function kidForDidKey(did: string): string;
export function jwsHeader(typ: string, kid: string): string;
export function signJws(a: { typ: string; kid: string; payload: unknown; privateKey: unknown }): string;
export function parseJws(jws: string): { header: { alg: string; kid: string; typ: string }; headerB64: string; signature: Uint8Array };
export function verifyJws(a: { jws: string; payload: unknown; typ: string; publicKey: Uint8Array }): boolean;
export function isIsoDate(s: unknown): boolean;
export const DID_UPDATE_TYP: 'sanad-did-update+jws';
/** Normative limits for one DID history: versions per history, keys and revocations per version. */
export const DID_LIMITS: { versions: number; keys: number; revoked: number };
export interface DidVersion { version: number; validFrom: string; keys: { id: string; publicKeyMultibase: string }[]; revoked: { id: string; from: string }[]; }
export interface DidHistory { id: string; versions: DidVersion[]; }
export interface Resolver {
  get(did: string): DidHistory | null;
  register(doc: DidHistory): DidHistory;
  update(did: string, version: DidVersion, jws: string): DidHistory;
  keysAt(did: string, date: string): { kid: string; publicKey: Uint8Array }[];
  keyAt(did: string, kid: string, date: string): { kid: string; publicKey: Uint8Array } | null;
  verifyStatement(a: { jws: string; payload: unknown; typ: string; signer: string; date: string }): { ok: true; kid: string; publicKey: Uint8Array } | { ok: false; reason: string };
}
export function createResolver(opts?: { store?: Pick<Store, 'get' | 'put'> }): Resolver;

// ---- storage
export interface Store {
  get(collection: string, id: string): any | null;
  put(collection: string, id: string, value: unknown): void;
  list(collection: string): any[];
  append(stream: string, value: unknown): number;
  read(stream: string, from?: number, to?: number): any[];
  size(stream: string): number;
  close(): void;
}
export function createMemoryStore(): Store;
export function createFileStore(dir: string): Store;
export function createSqliteStore(opts?: { path?: string; db?: unknown; prefix?: string }): Store;
export function sqliteAvailable(): boolean;
export function openStore(spec: string | { type: 'memory' | 'file' | 'sqlite'; [k: string]: unknown }): Store;

// ---- policy and templates
/** A verifier policy. Every field, including asOf, is required and range-checked; there is no partial policy. */
export interface Policy {
  minAttestors: number; requireLive: boolean; halfLifeMonths: number; minAttestorSittings: number; minAgreement: number;
  maxInferenceDepth: number; inferenceDecay: number; asOf: string;
}
export interface Template {
  id: string; version: number; title: string; description?: string;
  skill: { id: string; title: string; graphHash?: string; xwalk?: Json };
  levels: { level: Level; label: string }[];
  rubric?: { id: string; criterion: string; descriptors: Record<string, string> }[];
  evidence: { key: string; kind: 'auto' | 'sitting' | 'artifact' | 'peer'; summary: string; live?: boolean; minutes?: number }[];
  attestors: { min: number; max: number; roles: string[] };
  liveSitting: boolean; deadlines: { commitHours: number; revealHours: number };
  levelMap?: Record<string, Level>;
  policy: Omit<Policy, 'asOf'> & { id: string };
}
export function validateTemplate(t: unknown): { ok: boolean; errors: string[] };
export function assertTemplate<T>(t: T): T;
export function templateHash(t: Template): string;
export function policyFromTemplate(t: Template, asOf: string): Policy;
/** Problems with a policy; empty means usable. */
export function validatePolicy(p: unknown): string[];
export function levelFromNative(levelMap: Record<string, Level> | undefined, native: string): Level;
export function nonceWithNative(native: string, random: string): string;
export function nativeOfNonce(nonce: string): string | null;

// ---- statements
export const NONCE_RE: RegExp;
export function newNonce(): string;
export function commitFor(a: { attestor: string; evidence: string; level: Level; nonce: string }): string;
export interface CommitStatement { type: 'sanad-commit'; assessment: string; attestationId: string; attestor: string; evidence: string; role: string; commit: string; templateHash: string; }
export function commitStatement(a: Omit<CommitStatement, 'type'>): CommitStatement;
export interface AttestationStatement { id: string; attestor: string; evidence: string; level: Level; role: string; conflictDeclared: boolean; date: string; commit: string; nonce: string; }
export function attestationStatement(a: AttestationStatement): AttestationStatement;
export function checkCommit(a: { payload: unknown; invitation: Invitation; assessment: { id: string; templateHash: string } }): void;
export function checkReveal(a: { statement: unknown; invitation: Invitation; storedCommit: string; evidenceDate?: string; revealDay?: string; allowedLevels?: number[] }): void;

export interface Invitation { attestationId: string; attestor: string; role: string; evidence: string; invitedAt: string; }
export interface CommitRequest { attestationId: string; payload: CommitStatement; jws: string; }
export interface RevealRequest { attestationId: string; statement: AttestationStatement; jws: string; }
export interface SigningTicket {
  ticketVersion: 1; alg: 'sanad-0.1'; assessment: string; attestationId: string; attestor: string; role: string; evidence: string; templateHash: string;
  levels: Level[]; levelMap?: Record<string, Level>; commitBy: string; revealBy: string; state: 'open' | 'finalized'; revealOpen: boolean; serverTime: string; serverDay: string;
  rules: { nonce: { pattern: string; minLength: number; hint: string }; date: { format: string; notBefore: string; notAfter: string }; level: string };
  commit: { typ: string; type: string; members: string[]; commit: string; post: string };
  attestation: { typ: string; members: string[]; id: string; post: string };
}
type SignerLike = { did: string; sign(typ: string, payload: unknown): string };
export function prepareCommit(a: { signer: SignerLike; assessment?: { id: string; templateHash: string; invitations: Invitation[] }; ticket?: SigningTicket; attestationId?: string; level?: Level; native?: string; levelMap?: Record<string, Level>; nonce?: string }): { request: CommitRequest; secret: { attestationId: string; level: Level; nonce: string } };
export function prepareReveal(a: { signer: SignerLike; assessment?: { invitations: Invitation[] }; ticket?: SigningTicket; attestationId?: string; secret: { attestationId: string; level: Level; nonce: string }; date: string; conflictDeclared?: boolean }): RevealRequest;

// ---- assessments, credentials, verification
export interface AssessmentView {
  id: string; templateId: string; templateHash: string; subject: string; claimedLevel: Level; evidence: object[];
  commitBy: string; revealBy: string; createdAt: string; invitations: Invitation[]; removed: { attestationId: string; attestor: string; role: string; evidence: string; removedAt: string }[];
  commits: Record<string, { commit: string; payload: CommitStatement; jws: string; at: string }>;
  reveals: Record<string, { statement: AttestationStatement; jws: string; at: string }>;
  late: string[]; state: 'open' | 'finalized'; credentialId: string | null; revealOpen: boolean;
}
export interface Credential {
  '@context': string[]; type: string[]; id: string; issuer: string; validFrom: string;
  credentialSubject: { id: string; skill: string; claimedLevel: Level }; evidence: object[];
  sanad: { bundle: any; template: { id: string; hash: string }; assessment: string; process: { invited: number; committed: number; revealed: number; missing: string[]; late: string[]; notCommitted: string[]; removed?: string[]; shortfall?: string[] }; policy: object; log: any; dids: DidHistory[] };
  proof: { type: string; verificationMethod: string; created: string; jws: string };
}
export interface Check { name: string; ok: boolean; detail: string; }
export interface VerifyReport {
  ok: boolean; checks: Check[];
  /** When `ok` is false and a recognition is present it carries `unverified: true`: it is what the data would give if it were genuine. */
  recognition: (Core.Recognition & { unverified?: true }) | null; inferred: any[]; warnings: string[];
  basis: { policySource: 'verifier' | 'issuer-recommendation'; asOfSource: 'policy' | 'option' | 'verifier-clock' | 'credential-date' } | null;
  /** The experimental-software notice, repeated in every report. */
  notice: string;
}
/** What the verifier decides. Nothing here is defaulted from the issuer's document except through the explicit useRecommendedPolicy. */
export interface VerifyOptions {
  /** The verifier's own policy: all seven fields and asOf (asOf may come from `asOf`, or `useVerifierClock`). */
  policy?: Omit<Policy, 'asOf'> & { asOf?: string };
  /** Explicit opt-in to the issuer's recommended policy and the credential's date; the report labels it. */
  useRecommendedPolicy?: boolean;
  asOf?: string; useVerifierClock?: boolean; now?: number | Date;
  trustedIssuers?: string[]; trustedLogKeys?: string[]; trustedLogIds?: string[];
  /** did:web keys the verifier pins: { did: [publicKeyMultibase] }. Keys, not DID strings, are what is trusted. */
  pinnedKeys?: Record<string, string[]>;
  /** DID histories the verifier supplies itself (authoritative, unlike the ones embedded in the credential). */
  trustedDidHistories?: DidHistory[];
  resolver?: Resolver;
  /** Accept an issuer or log key that is not pinned (the report warns). */
  allowUnpinned?: boolean;
  /** Insecure: trust DID histories embedded in the credential. */
  allowEmbeddedDids?: boolean;
  /** The verifier's own statistics; they replace the issuer's. */
  attestorStats?: Record<string, { sittings: number; agreement: number }>;
  /** Accept issuer-supplied statistics for a sittings or agreement threshold (the report warns). */
  allowIssuerStatistics?: boolean;
  allowedAttestors?: string[];
  template?: Template;
  /** Examine the rest of a document whose issuer proof failed (by default verification stops there). */
  diagnose?: boolean;
  graph?: { requires(id: string): readonly string[] };
}
export function verifyCredential(doc: unknown, opts?: VerifyOptions): VerifyReport;
export const VERIFY_LIMITS: { attestations: number; evidence: number; logEntries: number; dids: number; versionsPerHistory: number; keysPerVersion: number; revokedPerVersion: number };
export const NOTICE: string;
export const CREDENTIAL_TYP: 'sanad-credential+jws';
export const ATTESTATION_TYP: 'sanad-attestation+jws';
export function sealBundle(a: { skill: string; claimedLevel: Level; subject: string; evidence: object[]; attestations: { statement: AttestationStatement; signature: string }[]; attestors: Record<string, { sittings: number; agreement: number }> }): any;
export function bundleHashOf(bundle: any): string;
export function buildCredential(a: { bundle: any; issuer: Signer; template: { id: string; hash: string }; assessment: string; process: object; policy: object; log: object; dids?: DidHistory[]; now: number | string | Date; id?: string }): Credential;
export function attestorStats(records: { evidence: { id: string; kind: string }[]; marks: { attestor: string; evidence: string; level: number }[] }[]): Record<string, { sittings: number; agreement: number }>;

export interface RecognitionPreview {
  preview: true; provisional: true; state: 'open' | 'finalized'; policySource: 'verifier-supplied' | 'template-recommendation';
  counts: { invited: number; committed: number; revealed: number; pending: number; notCommitted: number };
  recognition: Core.Recognition; note: string;
}
export interface Engine {
  registerTemplate(t: Template): { id: string; hash: string };
  getTemplate(id: string): Template;
  listTemplates(): { id: string; hash: string; title: string; version: number }[];
  registerDid(doc: DidHistory): DidHistory;
  updateDid(did: string, version: DidVersion, jws: string): DidHistory;
  createAssessment(a: { templateId: string; subject: string; subjectDid?: string; claimedLevel: Level; evidence: { key: string; date: string; summary: string; body: object }[]; commitBy?: string; revealBy?: string; id?: string }): AssessmentView;
  invite(assessmentId: string, i: { attestor: string; role: string; evidence: string }): Invitation;
  /** Declare the roster final; the reveal phase can then open once everyone invited has committed. */
  closeInvitations(assessmentId: string): { closed: true; invited: number };
  removeInvitation(assessmentId: string, attestationId: string, opts?: { reason?: string }): { removed: string; invited: number };
  ticketFor(assessmentId: string, attestationId: string): SigningTicket;
  commit(assessmentId: string, req: CommitRequest): { committed: number; of: number };
  reveal(assessmentId: string, req: RevealRequest): { revealed: number; of: number };
  previewRecognition(assessmentId: string, opts?: { policy?: Omit<Policy, 'asOf'> & { asOf?: string } }): RecognitionPreview;
  /** Enforces the template's attestor minimum and live sitting; `allowShortfall` is the operator's recorded override. Safe to retry after a crash. */
  finalize(assessmentId: string, opts?: { allowShortfall?: boolean }): Credential;
  getAssessment(id: string, opts?: { view?: 'public' | 'operator' }): AssessmentView;
  getCredential(id: string): Credential;
  listAssessments(): { id: string; templateId: string; subject: string; state: string; credentialId: string | null; createdAt: string }[];
  /** Pins this engine's own issuer, log key and log id and its template by default; policy and day are never defaulted. */
  verifyCredential(doc: unknown, opts?: VerifyOptions): VerifyReport;
  stats(did?: string): any;
  log: Log;
  resolver: Resolver;
  info(): { engine: string; alg: string; issuer: string; logId: string; logKey: string; time: string; today: string };
}
export function createEngine(cfg: { store: Store; issuer: Signer; logSigner: Signer; logId?: string; resolver?: Resolver; clock?: Clock }): Engine;

// ---- transparency log
export interface Checkpoint { payload: { logId: string; size: number; rootHash: string; timestamp: string }; jws: string | null; }
export interface Log {
  logId: string;
  append(a: { kind: 'commit' | 'attestation' | 'missing-reveal' | 'bundle'; ref: string }): { index: number; leaf: string; leafHash: string };
  appendOnce(a: { kind: 'commit' | 'attestation' | 'missing-reveal' | 'bundle'; ref: string }): { index: number; leaf: string; leafHash: string; existed: boolean };
  size(): number; root(size?: number): string;
  entries(from?: number, to?: number): { index: number; leaf: string; leafHash: string; prev: string; hash: string }[];
  inclusion(index: number, size?: number): { index: number; size: number; leafHash: string; proof: string[]; root: string };
  consistency(m: number, n?: number): { m: number; n: number; proof: string[]; rootM: string; rootN: string };
  checkpoint(): Checkpoint;
  verifyChain(): { ok: boolean; at?: number };
  findByRef(ref: string): object[];
}
export function createLog(a: { store: Store; stream?: string; logId: string; signer?: Signer | null; clock?: Clock }): Log;
export function leafHash(bytes: string | Uint8Array): string;
export function nodeHash(left: string, right: string): string;
export function merkleRoot(leafHashes: string[]): string;
export function inclusionProof(leafHashes: string[], index: number, size: number): string[];
export function consistencyProof(leafHashes: string[], m: number, n: number): string[];
export function isIsoTime(ts: unknown): boolean;
export function leafBytes(a: { kind: string; ref: string; ts: string }): string;
export function verifyInclusion(a: { leafHash: string; index: number; size: number; proof: string[]; root: string }): boolean;
export function verifyConsistency(a: { m: number; n: number; proof: string[]; rootM: string; rootN: string }): boolean;
export function verifyCheckpoint(checkpoint: Checkpoint, verify: (jws: string, payload: object, typ: string) => boolean): boolean;

// ---- I-JSON guards and HTTP
export const MAX_DEPTH: number;
export function scanJsonText(text: string, opts?: { maxDepth?: number }): void;
export function checkIJson<T>(value: T, opts?: { maxDepth?: number }): T;
export function createHttpServer(opts: { engine: Engine; operatorToken: string; serveStatic?: boolean; onError?: (message: string) => void }): Server;
export const BODY_LIMIT: number;
export const CSP: string;
export const STATIC_DIR: string;

export const core: typeof Core;
export const demo: { createDemoAttestor(name: string, seed?: Uint8Array | string): { name: string; did: string; kid: string; signer: Signer; privateKeyPkcs8: string } };
