// Sitting evidence: the members of the hashed body of an evidence item of kind `sitting` (SPEC section 3.3), their checks and the
// identity-assurance statement. Nothing here is a video or a name: only hashes, counters and one signed statement about how identity was checked.
import { isIsoDate, base58btcDecode, isSmallOrderKey } from './keys.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;
const METHOD_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactly = (o, names) => { const k = Object.keys(o).sort(); const n = [...names].sort(); return k.length === n.length && k.every((x, i) => x === n[i]); };

/** Identity assurance levels, lowest first. A0: not checked by anyone but the candidate; A1: checked by an examiner or registrar (document shown on camera, known person); A2: checked against an official document in person or by a registrar who holds a copy. A level says how identity was checked, never that it was honest. */
export const IDENTITY_LEVELS = ['A0', 'A1', 'A2'];
export const identityRank = (level) => IDENTITY_LEVELS.indexOf(level);
export const IDENTITY_TYP = 'sanad-identity+jws';
/** Members of a sitting body that this module knows. Any other member stays free JSON. */
export const SITTING_MEMBERS = ['sittingId', 'paperFingerprint', 'strokeLogHead', 'recordingSha256', 'recordingCipherSha256', 'recordingBytes', 'identityAssurance', 'publication'];
export const PUBLICATION_SCOPES = ['hashes', 'bundle'];

/** The statement a checker signs with typ sanad-identity+jws. It is bound to the sitting (sittingId) and to the candidate's key. */
export function identityStatement({ sittingId, level, method, checkedBy, date, candidateKey }) {
  return { type: 'sanad-identity', sittingId, level, method, checkedBy, date, candidateKey };
}

/**
 * Builds the identityAssurance member: signs with `signer` ({ did, sign }), the person or service that checked identity.
 * @returns {{ level: string, method: string, checkedBy: string, date: string, candidateKey: string, signature: string }}
 */
export function signIdentityAssurance({ signer, sittingId, level, method, date, candidateKey }) {
  const st = identityStatement({ sittingId, level, method, checkedBy: signer.did, date, candidateKey });
  return { level, method, checkedBy: signer.did, date, candidateKey, signature: signer.sign(IDENTITY_TYP, st) };
}

const keyOk = (mb) => { try { if (typeof mb !== 'string' || !mb.startsWith('z') || mb.length > 80) return false; const raw = base58btcDecode(mb.slice(1)); return raw.length === 32 && !isSmallOrderKey(raw); } catch { return false; } };

/**
 * Shape problems of a sitting body (empty list = fine). Members that are present are checked; which members are required is a template decision
 * (`requireRecordingHash`, `requireStrokeLogHead`, `requireIdentityAssurance` on the evidence item), see `missingRequired`.
 * @param {object} body
 * @returns {string[]}
 */
export function sittingProblems(body) {
  const p = [];
  if (!isObj(body)) return ['body must be an object'];
  const hex = (k) => { if (k in body && !(typeof body[k] === 'string' && HEX64.test(body[k]))) p.push(k + ' must be 64 lower-case hex characters'); };
  if ('sittingId' in body && !(typeof body.sittingId === 'string' && ID_RE.test(body.sittingId))) p.push('sittingId must match ' + ID_RE);
  hex('paperFingerprint'); hex('strokeLogHead'); hex('recordingSha256'); hex('recordingCipherSha256');
  if ('recordingCipherSha256' in body && !('recordingSha256' in body)) p.push('recordingCipherSha256 needs recordingSha256');
  if ('recordingBytes' in body && !(Number.isSafeInteger(body.recordingBytes) && body.recordingBytes > 0)) p.push('recordingBytes must be a positive integer');
  if ('recordingSha256' in body && !('recordingBytes' in body)) p.push('recordingSha256 needs recordingBytes (a positive integer)');
  if ('recordingBytes' in body && !('recordingSha256' in body)) p.push('recordingBytes without recordingSha256');
  if ('identityAssurance' in body) {
    const ia = body.identityAssurance;
    if (!isObj(ia) || !exactly(ia, ['level', 'method', 'checkedBy', 'date', 'candidateKey', 'signature'])) p.push('identityAssurance has exactly level, method, checkedBy, date, candidateKey, signature');
    else {
      if (!IDENTITY_LEVELS.includes(ia.level)) p.push('identityAssurance.level must be one of ' + IDENTITY_LEVELS.join(', '));
      if (!(typeof ia.method === 'string' && METHOD_RE.test(ia.method))) p.push('identityAssurance.method must match ' + METHOD_RE);
      if (!(typeof ia.checkedBy === 'string' && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(ia.checkedBy) && ia.checkedBy.length <= 200)) p.push('identityAssurance.checkedBy must be a DID');
      if (!isIsoDate(ia.date)) p.push('identityAssurance.date must be YYYY-MM-DD');
      if (!keyOk(ia.candidateKey)) p.push('identityAssurance.candidateKey must be a multibase (z, base58btc) Ed25519 public key');
      if (typeof ia.signature !== 'string' || ia.signature.length === 0 || ia.signature.length > 400) p.push('identityAssurance.signature must be a detached JWS');
      if (!('sittingId' in body)) p.push('identityAssurance needs sittingId (the statement is bound to the sitting)');
    }
  }
  if ('publication' in body) {
    const pb = body.publication;
    if (!isObj(pb) || !Object.keys(pb).every((k) => ['scope', 'url', 'date'].includes(k)) || !('scope' in pb) || !('date' in pb)) p.push('publication has scope and date, and optionally url');
    else {
      if (!PUBLICATION_SCOPES.includes(pb.scope)) p.push('publication.scope must be one of ' + PUBLICATION_SCOPES.join(', '));
      if (!isIsoDate(pb.date)) p.push('publication.date must be YYYY-MM-DD');
      if ('url' in pb && !(typeof pb.url === 'string' && /^https?:\/\/[^\s]{1,300}$/.test(pb.url))) p.push('publication.url must be an http or https URL (the base of the static mirror)');
    }
  }
  return p;
}

/** The template flags a sitting evidence item can carry, and the member each one demands. */
export const REQUIRE_FLAGS = { requireRecordingHash: 'recordingSha256', requireStrokeLogHead: 'strokeLogHead', requireIdentityAssurance: 'identityAssurance' };

/** Members that the template item demands and the body lacks. `item` is the template's evidence entry (or null). */
export function missingRequired(body, item) {
  if (!isObj(item)) return [];
  return Object.entries(REQUIRE_FLAGS).filter(([flag, member]) => item[flag] === true && !(isObj(body) && member in body)).map(([, member]) => member);
}

/** Checks the identity signature with a resolver ({ verifyStatement }). Returns { ok, reason? }. */
export function checkIdentitySignature(body, resolver) {
  const ia = body?.identityAssurance;
  if (!isObj(ia)) return { ok: false, reason: 'no identityAssurance' };
  const st = identityStatement({ sittingId: body.sittingId, level: ia.level, method: ia.method, checkedBy: ia.checkedBy, date: ia.date, candidateKey: ia.candidateKey });
  const r = resolver.verifyStatement({ jws: ia.signature, payload: st, typ: IDENTITY_TYP, signer: ia.checkedBy, date: ia.date });
  return r.ok ? { ok: true } : { ok: false, reason: r.reason };
}
