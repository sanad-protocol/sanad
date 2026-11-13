// Revocation of credentials with a W3C Bitstring Status List (https://www.w3.org/TR/vc-bitstring-status-list/), purpose "revocation", one bit per credential.
// The list is itself a signed credential published as a static file; a credential carries a `credentialStatus` entry that names the list and its position.
import { gzipSync, gunzipSync } from 'node:zlib';
import { b64u, fromB64u } from './keys.mjs';
import { canonical } from './core.mjs';

export const STATUS_LIST_TYP = 'sanad-status-list+jws';
/** The W3C specification requires lists of at least 131,072 entries (16 KiB) so that a list does not single out a holder. */
export const MIN_LIST_BITS = 131072;
const MAX_LIST_BITS = 1 << 27; // 16 MiB of bits: a hard cap on what a verifier will decompress
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactly = (o, names) => { const k = Object.keys(o).sort(); const n = [...names].sort(); return k.length === n.length && k.every((x, i) => x === n[i]); };

/** A zero bitstring of `bits` bits (rounded up to whole bytes). */
export function newBitstring(bits = MIN_LIST_BITS) {
  if (!Number.isInteger(bits) || bits < MIN_LIST_BITS || bits > MAX_LIST_BITS) throw new RangeError('a status list holds ' + MIN_LIST_BITS + ' to ' + MAX_LIST_BITS + ' bits');
  return new Uint8Array(Math.ceil(bits / 8));
}
/** Bit order of the specification: index 0 is the most significant bit of the first byte. */
export function setBit(bytes, index, value = true) {
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length * 8) throw new RangeError('index outside the list');
  const m = 0x80 >> (index % 8);
  if (value) bytes[index >> 3] |= m; else bytes[index >> 3] &= ~m;
}
export function getBit(bytes, index) {
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length * 8) throw new RangeError('index outside the list');
  return (bytes[index >> 3] & (0x80 >> (index % 8))) !== 0;
}
/** "u" (multibase base64url, no padding) followed by the GZIP-compressed bitstring. */
export function encodeList(bytes) { return 'u' + b64u(gzipSync(Buffer.from(bytes))); }
export function decodeList(encoded) {
  if (typeof encoded !== 'string' || encoded[0] !== 'u') throw new Error('encodedList must be multibase base64url (prefix u)');
  const raw = gunzipSync(Buffer.from(fromB64u(encoded.slice(1))), { maxOutputLength: MAX_LIST_BITS / 8 });
  if (raw.length * 8 < MIN_LIST_BITS) throw new Error('the list is shorter than ' + MIN_LIST_BITS + ' bits');
  return new Uint8Array(raw);
}

/** The credentialStatus member of a credential: where its bit is. */
export function statusEntry({ listUrl, index }) {
  return { id: listUrl + '#' + index, type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: listUrl };
}
export function statusEntryProblems(e) {
  if (!isObj(e) || !exactly(e, ['id', 'type', 'statusPurpose', 'statusListIndex', 'statusListCredential'])) return ['credentialStatus has exactly id, type, statusPurpose, statusListIndex, statusListCredential'];
  const p = [];
  if (e.type !== 'BitstringStatusListEntry') p.push('credentialStatus.type must be BitstringStatusListEntry');
  if (e.statusPurpose !== 'revocation') p.push('credentialStatus.statusPurpose must be revocation');
  if (!(typeof e.statusListIndex === 'string' && /^(0|[1-9]\d{0,8})$/.test(e.statusListIndex))) p.push('credentialStatus.statusListIndex must be a decimal string');
  if (!(typeof e.statusListCredential === 'string' && /^https?:\/\/\S+$/.test(e.statusListCredential))) p.push('credentialStatus.statusListCredential must be a URL');
  else if (e.id !== e.statusListCredential + '#' + e.statusListIndex) p.push('credentialStatus.id must be <statusListCredential>#<statusListIndex>');
  return p;
}

/**
 * Builds and signs a BitstringStatusListCredential.
 * @param {{ url: string, issuer: { did: string, kid: string, sign: Function }, bytes: Uint8Array, now: number|string|Date, ttlHours?: number }} p
 */
export function buildStatusListCredential({ url, issuer, bytes, now, ttlHours = 168 }) {
  const validFrom = new Date(now).toISOString();
  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: url,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: issuer.did,
    validFrom,
    validUntil: new Date(Date.parse(validFrom) + ttlHours * 3600000).toISOString(),
    credentialSubject: { id: url + '#list', type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encodeList(bytes) },
  };
  return { ...doc, proof: { type: 'SanadDetachedJws', verificationMethod: issuer.kid, created: validFrom, jws: issuer.sign(STATUS_LIST_TYP, JSON.parse(JSON.stringify(doc))) } };
}

/**
 * Checks one credential against the status lists a verifier fetched. `resolver.verifyStatement` verifies the list's issuer signature.
 * Returns { ok, revoked, detail }: ok is true only when the list is genuine (signed by the credential's issuer), fresh at `now`, and the bit is 0.
 * @param {{ credential: object, lists: object[], now: number|string|Date, resolver: { verifyStatement: Function } }} p
 */
export function checkStatus({ credential, lists, now, resolver }) {
  const entry = credential?.credentialStatus;
  if (entry === undefined) return { ok: true, revoked: false, detail: 'the credential carries no credentialStatus', applicable: false };
  const bad = statusEntryProblems(entry);
  if (bad.length) return { ok: false, revoked: false, detail: bad.join('; '), applicable: true };
  const list = (Array.isArray(lists) ? lists : []).find((l) => isObj(l) && l.id === entry.statusListCredential);
  if (!list) return { ok: false, revoked: false, detail: 'the status list ' + entry.statusListCredential + ' was not supplied', applicable: true };
  try {
    const { proof, ...body } = list;
    if (!isObj(proof) || proof.type !== 'SanadDetachedJws') return { ok: false, revoked: false, detail: 'the status list has no Sanad proof', applicable: true };
    if (list.issuer !== credential.issuer) return { ok: false, revoked: false, detail: 'the status list is issued by ' + list.issuer + ', not by the credential\'s issuer', applicable: true };
    if (canonical(list.type) !== canonical(['VerifiableCredential', 'BitstringStatusListCredential']) || list.credentialSubject?.type !== 'BitstringStatusList' || list.credentialSubject?.statusPurpose !== 'revocation') return { ok: false, revoked: false, detail: 'the document is not a revocation BitstringStatusListCredential', applicable: true };
    const r = resolver.verifyStatement({ jws: proof.jws, payload: body, typ: STATUS_LIST_TYP, signer: list.issuer, date: String(list.validFrom).slice(0, 10) });
    if (!r.ok || r.kid !== proof.verificationMethod || proof.created !== list.validFrom) return { ok: false, revoked: false, detail: 'the status list signature is refused' + (r.ok ? '' : ' (' + r.reason + ')'), applicable: true };
    const t = new Date(now).getTime();
    if (!(Date.parse(list.validFrom) <= t)) return { ok: false, revoked: false, detail: 'the status list is dated after the evaluation time', applicable: true };
    if (list.validUntil !== undefined && !(t <= Date.parse(list.validUntil))) return { ok: false, revoked: false, detail: 'the status list expired at ' + list.validUntil + ' (a stale list can hide a revocation)', applicable: true };
    const bits = decodeList(list.credentialSubject.encodedList);
    const idx = Number(entry.statusListIndex);
    if (idx >= bits.length * 8) return { ok: false, revoked: false, detail: 'statusListIndex is outside the list', applicable: true };
    const revoked = getBit(bits, idx);
    return { ok: !revoked, revoked, detail: revoked ? `revoked: bit ${idx} of ${entry.statusListCredential} is set` : `bit ${idx} of ${entry.statusListCredential} is clear (list valid ${list.validFrom} to ${list.validUntil ?? 'no end'})`, applicable: true };
  } catch (e) { return { ok: false, revoked: false, detail: 'the status list is not usable: ' + (e?.message ?? e), applicable: true }; }
}
