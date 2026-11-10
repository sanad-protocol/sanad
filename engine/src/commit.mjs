// Commit and attestation statements, and the checks applied to a blind commit and to its reveal.
import { canonical, commitOf } from './core.mjs';
import { EngineError } from './errors.mjs';
import { isIsoDate } from './keys.mjs';

/** A nonce has at least 22 base64url characters (128 bits when random). */
export const NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** A fresh nonce: 16 random bytes as 22 base64url characters. */
export function newNonce() { return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).toString('base64url'); }

export function commitFor({ attestor, evidence, level, nonce }) { return commitOf({ attestor, evidence, level, nonce }); }

const isStr = (v) => typeof v === 'string' && v.length > 0;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const hasExactly = (o, names) => { const k = Object.keys(o).sort(); const n = [...names].sort(); return k.length === n.length && k.every((x, i) => x === n[i]); };

/** The statement an attestor signs with typ sanad-commit+jws. */
export function commitStatement({ assessment, attestationId, attestor, evidence, role, commit, templateHash }) {
  for (const [k, v] of Object.entries({ assessment, attestationId, attestor, evidence, role })) {
    if (!isStr(v)) throw new EngineError('bad_commit', k + ' must be a non-empty string');
  }
  if (typeof commit !== 'string' || !HEX64.test(commit)) throw new EngineError('bad_commit', 'commit must be 64 lowercase hex characters');
  if (typeof templateHash !== 'string' || !HEX64.test(templateHash)) throw new EngineError('bad_commit', 'templateHash must be 64 lowercase hex characters');
  return { type: 'sanad-commit', assessment, attestationId, attestor, evidence, role, commit, templateHash };
}

const ATTESTATION_MEMBERS = ['id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'commit', 'nonce'];

/** The statement an attestor signs with typ sanad-attestation+jws: the attestation without prev, hash and signature. */
export function attestationStatement({ id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce }) {
  return { id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce };
}

/** Checks a posted commit payload against the invitation and the assessment. Throws EngineError. */
export function checkCommit({ payload, invitation, assessment }) {
  if (!isObj(payload) || !hasExactly(payload, ['type', 'assessment', 'attestationId', 'attestor', 'evidence', 'role', 'commit', 'templateHash'])) {
    throw new EngineError('bad_commit', 'a commit statement has exactly type, assessment, attestationId, attestor, evidence, role, commit, templateHash');
  }
  if (typeof payload.commit !== 'string' || !HEX64.test(payload.commit)) throw new EngineError('bad_commit', 'commit must be 64 lowercase hex characters');
  const expected = commitStatement({
    assessment: assessment.id, attestationId: invitation.attestationId, attestor: invitation.attestor, evidence: invitation.evidence,
    role: invitation.role, commit: payload.commit, templateHash: assessment.templateHash,
  });
  if (canonical(payload) !== canonical(expected)) throw new EngineError('commit_mismatch_invitation', 'the commit statement does not match the invitation and the assessment');
}

/**
 * Checks a reveal. Throws EngineError with one of: bad_statement, statement_mismatch, bad_level, bad_date, bad_nonce, commit_mismatch.
 * Order: shape, invitation fields, level, date, nonce, then the commit.
 */
export function checkReveal({ statement, invitation, storedCommit, evidenceDate, revealDay, allowedLevels }) {
  const s = statement;
  if (!isObj(s) || !hasExactly(s, ATTESTATION_MEMBERS)) throw new EngineError('bad_statement', 'an attestation statement has exactly ' + ATTESTATION_MEMBERS.join(', '));
  for (const k of ['id', 'attestor', 'evidence', 'role', 'commit']) if (typeof s[k] !== 'string') throw new EngineError('bad_statement', k + ' must be a string');
  if (typeof s.conflictDeclared !== 'boolean') throw new EngineError('bad_statement', 'conflictDeclared must be true or false');
  if (s.id !== invitation.attestationId || s.attestor !== invitation.attestor || s.evidence !== invitation.evidence || s.role !== invitation.role) {
    throw new EngineError('statement_mismatch', 'id, attestor, evidence and role must equal the invitation');
  }
  const allowed = allowedLevels ?? [0, 1, 2, 3, 4, 5];
  if (!Number.isInteger(s.level) || s.level < 0 || s.level > 5 || !allowed.includes(s.level)) throw new EngineError('bad_level', 'level must be an integer from 0 to 5 that the template allows');
  if (!isIsoDate(s.date)) throw new EngineError('bad_date', 'date must be a valid YYYY-MM-DD');
  if (evidenceDate !== undefined && s.date < evidenceDate) throw new EngineError('bad_date', 'date is before the evidence date');
  if (revealDay !== undefined && s.date > revealDay) throw new EngineError('bad_date', 'date is after the reveal day');
  if (typeof s.nonce !== 'string' || !NONCE_RE.test(s.nonce)) throw new EngineError('bad_nonce', 'nonce must be 22 to 128 base64url characters');
  if (s.commit !== storedCommit || commitFor(s) !== storedCommit) throw new EngineError('commit_mismatch', 'the reveal does not match the stored commit');
}
