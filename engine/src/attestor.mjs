// Client-side helper for an attestor who holds a signer ({ did, kid, sign }). The engine never calls this with keys it holds:
// the attestor runs it on their own device and sends only the signed request and the signed reveal to the engine.
import { EngineError } from './errors.mjs';
import { NONCE_RE, newNonce, commitFor, commitStatement, attestationStatement } from './commit.mjs';

function invitationOf(assessment, attestationId, signer) {
  const inv = (assessment?.invitations ?? []).find((i) => i.attestationId === attestationId);
  if (!inv) throw new EngineError('not_invited', 'the assessment has no invitation ' + attestationId, 403);
  if (inv.attestor !== signer.did) throw new EngineError('not_invited', 'the invitation ' + attestationId + ' is for ' + inv.attestor + ', not for ' + signer.did, 403);
  return inv;
}

/**
 * Commit step. Keep `secret` on the attestor's device; send only `request` to the engine.
 * @returns {{ request: { attestationId: string, payload: object, jws: string }, secret: { attestationId: string, level: number, nonce: string } }}
 */
export function prepareCommit({ signer, assessment, attestationId, level, nonce }) {
  const inv = invitationOf(assessment, attestationId, signer);
  if (!Number.isInteger(level) || level < 0 || level > 5) throw new EngineError('bad_level', 'level must be an integer from 0 to 5');
  const n = nonce ?? newNonce();
  if (!NONCE_RE.test(n)) throw new EngineError('bad_nonce', 'nonce must be 22 to 128 base64url characters');
  const commit = commitFor({ attestor: inv.attestor, evidence: inv.evidence, level, nonce: n });
  const payload = commitStatement({ assessment: assessment.id, attestationId, attestor: inv.attestor, evidence: inv.evidence, role: inv.role, commit, templateHash: assessment.templateHash });
  return { request: { attestationId, payload, jws: signer.sign('sanad-commit+jws', payload) }, secret: { attestationId, level, nonce: n } };
}

/**
 * Reveal step: the signed attestation statement (without prev, hash and signature).
 * @returns {{ attestationId: string, statement: object, jws: string }}
 */
export function prepareReveal({ signer, assessment, attestationId, secret, date, conflictDeclared = false }) {
  const inv = invitationOf(assessment, attestationId, signer);
  if (!secret || secret.attestationId !== attestationId) throw new EngineError('bad_secret', 'the secret does not belong to ' + attestationId);
  const commit = commitFor({ attestor: inv.attestor, evidence: inv.evidence, level: secret.level, nonce: secret.nonce });
  const statement = attestationStatement({ id: attestationId, attestor: inv.attestor, evidence: inv.evidence, level: secret.level, role: inv.role, conflictDeclared, date, commit, nonce: secret.nonce });
  return { attestationId, statement, jws: signer.sign('sanad-attestation+jws', statement) };
}
