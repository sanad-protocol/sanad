// Builders that fill in the hashes, the blind-marking commit and the chain link, so examples (tests, the sample credential, vectors) are valid by construction.
// A real issuer does the same with its own keys; v0.1 signatures are placeholders.
import { hashOf } from './canon';
import type { Attestation, Credential, Evidence, Level } from './types';

export type EvidenceDraft = Omit<Evidence, 'hash'>;
export type AttestationDraft = { id: string; attestor: string; evidence: string; level: Level; role?: string; conflictDeclared?: boolean; date: string; nonce?: string };

export const evidenceHash = (e: Pick<Evidence, 'body'>) => hashOf(e.body);
/** What is hashed for the blind-marking commitment, and for an attestation. Exported so the page can recompute the same hashes with WebCrypto. */
export const commitPayload = (a: Pick<Attestation, 'attestor' | 'evidence' | 'level' | 'nonce'>) => ({ attestor: a.attestor, evidence: a.evidence, level: a.level, nonce: a.nonce });
export const attestationPayload = (a: Omit<Attestation, 'hash' | 'signature'> & { signature?: string }) => ({
  id: a.id, attestor: a.attestor, evidence: a.evidence, level: a.level, role: a.role, conflictDeclared: a.conflictDeclared, date: a.date, commit: a.commit, nonce: a.nonce, prev: a.prev,
});
export const commitOf = (a: Pick<Attestation, 'attestor' | 'evidence' | 'level' | 'nonce'>) => hashOf(commitPayload(a));
export const attestationHashOf = (a: Omit<Attestation, 'hash' | 'signature'> & { signature?: string }) => hashOf(attestationPayload(a));

export function sealEvidence(d: EvidenceDraft): Evidence { return { ...d, hash: evidenceHash(d) }; }
/** Seals attestations in id order, chaining each to the previous one. */
export function sealAttestations(drafts: AttestationDraft[]): Attestation[] {
  const out: Attestation[] = []; let prev = 'GENESIS';
  for (const d of [...drafts].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    const base = { id: d.id, attestor: d.attestor, evidence: d.evidence, level: d.level, role: d.role ?? 'examiner', conflictDeclared: d.conflictDeclared ?? false, date: d.date, nonce: d.nonce ?? 'n-' + d.id, prev };
    const commit = commitOf(base); const hash = attestationHashOf({ ...base, commit });
    out.push({ ...base, commit, hash, signature: 'unsigned-v0.1:' + hash }); prev = hash;
  }
  return out;
}
export function sealCredential(c: { skill: string; claimedLevel: Level; subject: string; evidence: EvidenceDraft[]; attestations: AttestationDraft[]; attestors: Credential['attestors'] }): Credential {
  return { skill: c.skill, claimedLevel: c.claimedLevel, subject: c.subject, evidence: c.evidence.map(sealEvidence), attestations: sealAttestations(c.attestations), attestors: c.attestors };
}
