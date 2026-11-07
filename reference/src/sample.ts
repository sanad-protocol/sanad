// The sample credential of the explainer page: Real analysis I (course B09), claimed level 4, built from invented people and invented evidence.
// Nothing here is a real person or a real sitting. Signatures are placeholders in v0.1.
import { sealCredential } from './seal';
import type { Credential } from './types';
import type { TamperOp } from './tamper';

export const SAMPLE_SKILL = 'B09';
export const SAMPLE_NAMES: Record<string, string> = { 'did:sanad:ember': 'Ember (examiner)', 'did:sanad:ash': 'Ash (examiner)', 'did:sanad:linden': 'Linden (reviewer)', 'did:sanad:fern': 'Fern (fellow learner)' };

export function sampleCredential(): Credential {
  return sealCredential({
    skill: SAMPLE_SKILL, claimedLevel: 4, subject: 'urn:uuid:7c1f0b2e-sample-learner',
    evidence: [
      { id: 'E1', kind: 'auto', date: '2026-09-14', summary: '40 seeded epsilon-delta exercises, replayed from their seeds', body: { autoLevel: 3, exercises: 40, seeds: ['K7Q', 'M2M', 'QF8', 'P6Q'], lecture: 'limits' } },
      { id: 'E2', kind: 'sitting', date: '2026-10-20', summary: 'Live sitting S-2026-014: 90 minutes, two examiners, whiteboard stroke log', body: { sitting: 'S-2026-014', minutes: 90, strokeLogHead: 'e3b0c442', paper: 'B09-proofs' } },
      { id: 'E3', kind: 'artifact', date: '2026-10-02', summary: 'Proof portfolio: three written proofs (hash of the PDF)', body: { file: 'portfolio.pdf', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', proofs: 3 } },
      { id: 'E4', kind: 'peer', date: '2026-09-30', summary: 'Peer review by a fellow learner', body: { reviewer: 'learner-7', rubric: 'epsilon-delta-v1' } },
    ],
    attestations: [
      { id: 'att-01', attestor: 'did:sanad:ember', evidence: 'E2', level: 4, role: 'examiner', date: '2026-10-21' },
      { id: 'att-02', attestor: 'did:sanad:ash', evidence: 'E2', level: 4, role: 'examiner', date: '2026-10-21' },
      { id: 'att-03', attestor: 'did:sanad:linden', evidence: 'E3', level: 4, role: 'reviewer', date: '2026-10-05' },
      { id: 'att-04', attestor: 'did:sanad:fern', evidence: 'E4', level: 3, role: 'peer', date: '2026-10-01' },
    ],
    attestors: { 'did:sanad:ember': { sittings: 14, agreement: 0.91 }, 'did:sanad:ash': { sittings: 9, agreement: 0.88 }, 'did:sanad:linden': { sittings: 6, agreement: 0.8 }, 'did:sanad:fern': { sittings: 1, agreement: 0.7 } },
  });
}
/** The forger's edit: Ash's mark 4 becomes 5, the stored hash is left alone. */
export const SAMPLE_TAMPER: TamperOp[] = [{ attestation: 'att-02', set: { level: 5 } }];
