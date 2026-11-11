// Type declarations for @sanad-protocol/engine 0.2.0 (algorithm sanad-0.1). The core recognition types live in @sanad-protocol/core.
import type { Server } from 'node:http';

export type Level = 0 | 1 | 2 | 3 | 4 | 5;
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export class EngineError extends Error { code: string; status: number; reason?: string; constructor(code: string, message?: string, status?: number); }

export interface Signer { did: string; kid: string; publicKey: Uint8Array; sign(typ: string, payload: unknown): string; }
export interface Clock { now(): number; }

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

export interface Policy { minAttestors: number; requireLive: boolean; halfLifeMonths: number; minAttestorSittings: number; minAgreement: number; maxInferenceDepth: number; inferenceDecay: number; }
export interface Template {
  id: string; version: number; title: string; description?: string;
  skill: { id: string; title: string; graphHash?: string; xwalk?: Json };
  levels: { level: Level; label: string }[];
  rubric?: { id: string; criterion: string; descriptors: Record<string, string> }[];
  evidence: { key: string; kind: 'auto' | 'sitting' | 'artifact' | 'peer'; summary: string; live?: boolean; minutes?: number }[];
  attestors: { min: number; max: number; roles: string[] };
  liveSitting: boolean; deadlines: { commitHours: number; revealHours: number };
  levelMap?: Record<string, Level>;
  policy: Policy & { id: string };
}
export function validateTemplate(t: unknown): { ok: boolean; errors: string[] };
export function assertTemplate<T>(t: T): T;
export function templateHash(t: Template): string;
export function policyFromTemplate(t: Template, asOf: string): Policy & { asOf: string };

export interface Invitation { attestationId: string; attestor: string; role: string; evidence: string; invitedAt: string; }
export interface CommitRequest { attestationId: string; payload: Record<string, unknown>; jws: string; }
export interface AttestationStatement { id: string; attestor: string; evidence: string; level: Level; role: string; conflictDeclared: boolean; date: string; commit: string; nonce: string; }
export interface RevealRequest { attestationId: string; statement: AttestationStatement; jws: string; }
export interface AssessmentView {
  id: string; templateId: string; templateHash: string; subject: string; claimedLevel: Level; evidence: object[];
  commitBy: string; revealBy: string; createdAt: string; invitations: Invitation[];
  commits: Record<string, { commit: string; payload: object; jws: string; at: string }>;
  reveals: Record<string, { statement: AttestationStatement; jws: string; at: string }>;
  late: string[]; state: 'open' | 'finalized'; credentialId: string | null; revealOpen: boolean;
}
export interface Check { name: string; ok: boolean; detail: string; }
export interface VerifyReport { ok: boolean; checks: Check[]; recognition: any | null; inferred: any[]; warnings: string[]; }
export interface VerifyOptions { policy?: Partial<Policy> & { asOf?: string }; resolver?: unknown; trustedIssuers?: string[]; trustedLogKeys?: string[]; asOf?: string; graph?: object; }
export interface Credential { '@context': string[]; type: string[]; id: string; issuer: string; validFrom: string; credentialSubject: { id: string; skill: string; claimedLevel: Level }; evidence: object[]; sanad: any; proof: { type: string; verificationMethod: string; created: string; jws: string }; }

export interface Engine {
  registerTemplate(t: Template): { id: string; hash: string };
  getTemplate(id: string): Template;
  listTemplates(): { id: string; hash: string; title: string; version: number }[];
  registerDid(doc: { id: string; versions: object[] }): object;
  updateDid(did: string, version: object, jws: string): object;
  createAssessment(a: { templateId: string; subject: string; claimedLevel: Level; evidence: { key: string; date: string; summary: string; body: object }[]; commitBy?: string; revealBy?: string; id?: string }): AssessmentView;
  invite(assessmentId: string, i: { attestor: string; role: string; evidence: string }): Invitation;
  commit(assessmentId: string, req: CommitRequest): { committed: number; of: number };
  reveal(assessmentId: string, req: RevealRequest): { revealed: number; of: number };
  finalize(assessmentId: string): Credential;
  getAssessment(id: string, opts?: { view?: 'public' | 'operator' }): AssessmentView;
  getCredential(id: string): Credential;
  listAssessments(): object[];
  verifyCredential(doc: unknown, opts?: VerifyOptions): VerifyReport;
  stats(did?: string): any;
  log: any;
  resolver: any;
  info(): { engine: string; alg: string; issuer: string; logId: string; logKey: string };
}
export function createEngine(cfg: { store: Store; issuer: Signer; logSigner: Signer; logId?: string; resolver?: unknown; clock?: Clock }): Engine;
/** Verification needs no engine instance and no data directory. */
export function verifyCredential(doc: unknown, opts?: VerifyOptions): VerifyReport;

export function prepareCommit(a: { signer: { did: string; sign(typ: string, payload: unknown): string }; assessment: { id: string; templateHash: string; invitations: Invitation[] }; attestationId: string; level: Level; nonce?: string }): { request: CommitRequest; secret: { attestationId: string; level: Level; nonce: string } };
export function prepareReveal(a: { signer: { did: string; sign(typ: string, payload: unknown): string }; assessment: { invitations: Invitation[] }; attestationId: string; secret: { attestationId: string; level: Level; nonce: string }; date: string; conflictDeclared?: boolean }): RevealRequest;

export function generateKeyPair(): any;
export function keyPairFromSeed(seed: Uint8Array): any;
export function makeSigner(privateKey: unknown, did?: string): Signer;
export function exportPrivateKey(privateKey: unknown): string;
export function importPrivateKey(s: string): unknown;
export function didKeyFromPublicKey(raw: Uint8Array): string;
export function publicKeyFromDidKey(did: string): Uint8Array;
export function createResolver(opts?: { store?: Pick<Store, 'get' | 'put'> }): any;

export function createHttpServer(opts: { engine: Engine; operatorToken: string; serveStatic?: boolean }): Server;
export const BODY_LIMIT: number;
export const CSP: string;
export const core: Record<string, any>;
export const demo: { createDemoAttestor(name: string, seed?: Uint8Array | string): { name: string; did: string; kid: string; signer: Signer; privateKeyPkcs8: string } };
