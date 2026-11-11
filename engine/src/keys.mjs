// Ed25519 keys, did:key, detached JWS and a resolver for DID document histories (rotation and revocation).
// Only Node built-ins are used. Attestor private keys never enter the engine; this module only handles them where a caller passes one in.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import { canonical } from './core.mjs';
import { EngineError } from './errors.mjs';

const enc = new TextEncoder();
// ignoreBOM keeps a leading byte-order mark in the text, so a header with a BOM fails the canonical-form check instead of being silently accepted.
const dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Base64url without padding. */
export function b64u(bytes) { return Buffer.from(bytes).toString('base64url'); }

/** Strict base64url decoding: only the url-safe alphabet, no padding, and only the canonical encoding of the bytes. */
export function fromB64u(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('not base64url');
  const out = new Uint8Array(Buffer.from(s, 'base64url'));
  if (b64u(out) !== s) throw new Error('not canonical base64url');
  return out;
}

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHA_INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));

/** Base58 (bitcoin alphabet); each leading zero byte becomes a leading '1'. */
export function base58btcEncode(bytes) {
  const b = Uint8Array.from(bytes);
  let zeros = 0; while (zeros < b.length && b[zeros] === 0) zeros++;
  let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x);
  let s = ''; while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
  return '1'.repeat(zeros) + s;
}

export function base58btcDecode(str) {
  if (typeof str !== 'string') throw new Error('not a string');
  let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++;
  let n = 0n;
  for (const c of str) { const v = ALPHA_INDEX.get(c); if (v === undefined) throw new Error('bad base58 character'); n = n * 58n + BigInt(v); }
  const hex = n === 0n ? '' : n.toString(16);
  const body = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  const out = new Uint8Array(zeros + body.length); out.set(body, zeros);
  return out;
}

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Raw 32-byte public key of a private KeyObject. */
export function publicKeyOf(privateKey) {
  const der = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return new Uint8Array(der.subarray(SPKI_PREFIX.length));
}
function shape(privateKey) { return { publicKey: publicKeyOf(privateKey), privateKey }; }

export function generateKeyPair() { return shape(generateKeyPairSync('ed25519').privateKey); }

export function keyPairFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('seed must be 32 bytes');
  return shape(createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' }));
}

export function exportPrivateKey(privateKey) { return b64u(privateKey.export({ type: 'pkcs8', format: 'der' })); }
export function importPrivateKey(str) { return createPrivateKey({ key: Buffer.from(fromB64u(str)), format: 'der', type: 'pkcs8' }); }

// Ed25519 keys of small order (the identity and the other seven torsion points) verify one fixed signature over every message, so no signer is
// bound to such a key. A point is of small order when eight times the point is the identity (curve arithmetic below, plain BigInt, affine).
const P25519 = 2n ** 255n - 19n;
const D25519 = ((P25519 - 121665n * modPow(121666n, P25519 - 2n, P25519) % P25519) % P25519 + P25519) % P25519;
function modPow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const inv = (a) => modPow(((a % P25519) + P25519) % P25519, P25519 - 2n, P25519);
const SMALL_CACHE = new Map(); // hex -> boolean; bounded, so a flood of distinct keys cannot grow memory
/** True when the 32 bytes are not an Ed25519 point or are a point of order 1, 2, 4 or 8. Results are cached (the check is BigInt arithmetic). */
export function isSmallOrderKey(raw32) {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) return true;
  const k = Buffer.from(raw32).toString('hex');
  const hit = SMALL_CACHE.get(k);
  if (hit !== undefined) return hit;
  const v = computeSmallOrder(raw32);
  if (SMALL_CACHE.size >= 1024) SMALL_CACHE.delete(SMALL_CACHE.keys().next().value);
  SMALL_CACHE.set(k, v);
  return v;
}
function computeSmallOrder(raw32) {
  let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(raw32[i]);
  y &= (1n << 255n) - 1n; y %= P25519;
  const y2 = y * y % P25519;
  const u = (y2 - 1n + P25519) % P25519, v = (D25519 * y2 + 1n) % P25519;
  const t = u * inv(v) % P25519;
  let x = modPow(t, (P25519 + 3n) / 8n, P25519);
  if (x * x % P25519 !== t) x = x * modPow(2n, (P25519 - 1n) / 4n, P25519) % P25519;
  if (x * x % P25519 !== t) return true; // not on the curve
  const add = (a, b) => {
    const k = D25519 * a[0] % P25519 * a[1] % P25519 * b[0] % P25519 * b[1] % P25519;
    return [(a[0] * b[1] + b[0] * a[1]) % P25519 * inv(1n + k) % P25519, (a[1] * b[1] + a[0] * b[0]) % P25519 * inv(1n - k) % P25519];
  };
  let q = [x, y]; for (let i = 0; i < 3; i++) q = add(q, q);
  return q[0] === 0n && q[1] === 1n;
}

function publicKeyObject(raw32) { return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: 'der', type: 'spki' }); }

const DID_KEY = 'did:key:';
export function didKeyFromPublicKey(raw32) {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) throw new Error('public key must be 32 bytes');
  return DID_KEY + 'z' + base58btcEncode(Uint8Array.from([0xed, 0x01, ...raw32]));
}
export function publicKeyFromDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith(DID_KEY + 'z')) throw new Error('not a did:key with a base58btc key');
  if (did.length > 80) throw new Error('did:key is too long');
  const bytes = base58btcDecode(did.slice(DID_KEY.length + 1));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error('not an Ed25519 did:key');
  const key = bytes.slice(2);
  if (isSmallOrderKey(key)) throw new Error('key is not usable (small order or not on the curve)');
  return key;
}
export function kidForDidKey(did) { return did + '#' + did.slice(DID_KEY.length); }

/** Canonical JSON text of the JWS header. */
export function jwsHeader(typ, kid) { return canonical({ alg: 'EdDSA', kid, typ }); }

const signingInput = (headerB64, payload) => headerB64 + '.' + b64u(enc.encode(canonical(payload)));

/** Detached compact JWS: B64U(header) + '..' + B64U(signature). */
export function signJws({ typ, kid, payload, privateKey }) {
  const headerB64 = b64u(enc.encode(jwsHeader(typ, kid)));
  const sig = edSign(null, Buffer.from(signingInput(headerB64, payload), 'utf8'), privateKey);
  return headerB64 + '..' + b64u(sig);
}

/** Strict parse of a detached JWS. Throws on anything that is not the one accepted form. */
export function parseJws(jws) {
  if (typeof jws !== 'string') throw new Error('JWS must be a string');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('JWS must have three parts');
  if (parts[1] !== '') throw new Error('JWS payload must be detached');
  const headerBytes = fromB64u(parts[0]);
  const header = JSON.parse(dec.decode(headerBytes));
  if (header === null || typeof header !== 'object' || Array.isArray(header)) throw new Error('header must be an object');
  const names = Object.keys(header).sort();
  if (names.length !== 3 || names[0] !== 'alg' || names[1] !== 'kid' || names[2] !== 'typ') throw new Error('header members must be exactly alg, kid, typ');
  if (header.alg !== 'EdDSA') throw new Error('alg must be EdDSA');
  if (typeof header.kid !== 'string' || typeof header.typ !== 'string') throw new Error('kid and typ must be strings');
  if (dec.decode(headerBytes) !== canonical(header)) throw new Error('header is not in canonical form');
  const signature = fromB64u(parts[2]);
  if (signature.length !== 64) throw new Error('signature must be 64 bytes');
  return { header, headerB64: parts[0], signature };
}

/** True only if the JWS is well formed, has the expected typ and verifies over the canonical payload. Never throws. */
export function verifyJws({ jws, payload, typ, publicKey }) {
  try {
    const { header, headerB64, signature } = parseJws(jws);
    if (header.typ !== typ) return false;
    if (isSmallOrderKey(publicKey)) return false;
    return edVerify(null, Buffer.from(signingInput(headerB64, payload), 'utf8'), publicKeyObject(publicKey), signature);
  } catch { return false; }
}

export function makeSigner(privateKey, did) {
  const publicKey = publicKeyOf(privateKey);
  const id = did ?? didKeyFromPublicKey(publicKey);
  const kid = did === undefined ? kidForDidKey(id) : id + '#k1';
  return { did: id, kid, publicKey, sign: (typ, payload) => signJws({ typ, kid, payload, privateKey }) };
}

// ---------------------------------------------------------------------------------------------------------------------
// DID document histories

export function isIsoDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  // years below 100 are refused as well: the core's dayNumber reads them as 19xx, so the two would disagree
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s && Number(s.slice(0, 4)) >= 100;
}

const KEY_ID_RE = /^#[A-Za-z0-9._-]{1,64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const exactly = (o, names) => { const k = Object.keys(o).sort(); return k.length === names.length && names.every((n, i) => k[i] === n); };
const clone = (v) => JSON.parse(JSON.stringify(v));

function rawFromMultibase(s) {
  if (typeof s !== 'string' || !s.startsWith('z') || s.length > 80) throw new Error('multibase must start with z');
  const raw = base58btcDecode(s.slice(1));
  if (raw.length !== 32) throw new Error('key must be 32 bytes');
  if (isSmallOrderKey(raw)) throw new Error('key is not usable (small order or not on the curve)');
  return raw;
}

/** Checks one version object; throws a plain Error with the reason. */
function checkVersion(v, { expectRevokedEmpty }) {
  if (!isObj(v) || !exactly(v, ['keys', 'revoked', 'validFrom', 'version'])) throw new Error('a version has exactly version, validFrom, keys, revoked');
  if (!Number.isInteger(v.version) || v.version < 1) throw new Error('version must be a positive integer');
  if (!isIsoDate(v.validFrom)) throw new Error('validFrom must be YYYY-MM-DD');
  if (!Array.isArray(v.keys) || v.keys.length === 0) throw new Error('keys must be a non-empty array');
  const ids = new Set();
  for (const k of v.keys) {
    if (!isObj(k) || !exactly(k, ['id', 'publicKeyMultibase'])) throw new Error('a key has exactly id and publicKeyMultibase');
    if (typeof k.id !== 'string' || !KEY_ID_RE.test(k.id)) throw new Error('bad key id');
    if (ids.has(k.id)) throw new Error('duplicate key id');
    ids.add(k.id); rawFromMultibase(k.publicKeyMultibase);
  }
  if (!Array.isArray(v.revoked)) throw new Error('revoked must be an array');
  if (expectRevokedEmpty && v.revoked.length) throw new Error('version 1 has no revocations');
  for (const r of v.revoked) {
    if (!isObj(r) || !exactly(r, ['from', 'id'])) throw new Error('a revocation has exactly id and from');
    if (typeof r.id !== 'string' || !KEY_ID_RE.test(r.id) || !isIsoDate(r.from)) throw new Error('bad revocation');
  }
}

export const DID_UPDATE_TYP = 'sanad-did-update+jws';

/**
 * A resolver for signer keys. did:key resolves by itself; any other DID needs a registered history.
 * @param {{ store?: { get(c: string, id: string): any, put(c: string, id: string, v: any): void } }} [opts]
 */
export function createResolver({ store } = {}) {
  const mem = new Map();
  const load = (did) => {
    const v = store ? store.get('dids', did) : mem.get(did);
    return v ? clone(v) : null;
  };
  const save = (did, doc) => { if (store) store.put('dids', did, doc); else mem.set(did, clone(doc)); };

  const resolver = {
    get(did) { return load(did); },

    register(doc) {
      const bad = (m) => new EngineError('bad_did_document', m, 400);
      if (!isObj(doc) || !exactly(doc, ['id', 'versions'])) throw bad('a DID document history has exactly id and versions');
      if (typeof doc.id !== 'string' || !/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(doc.id) || doc.id.length > 200) throw bad('bad DID');
      if (doc.id.startsWith(DID_KEY)) throw new EngineError('bad_did_document', 'did:key needs no registration', 400);
      if (!Array.isArray(doc.versions) || doc.versions.length !== 1) throw bad('registration carries exactly version 1');
      const v = doc.versions[0];
      try { checkVersion(v, { expectRevokedEmpty: true }); } catch (e) { throw bad(e.message); }
      if (v.version !== 1) throw bad('the first version must be 1');
      if (load(doc.id)) throw new EngineError('did_exists', 'DID already registered: ' + doc.id, 409);
      save(doc.id, { id: doc.id, versions: [clone(v)] });
      return load(doc.id);
    },

    update(did, version, jws) {
      const hist = load(did);
      if (!hist) throw new EngineError('did_unknown', 'DID not registered: ' + did, 404);
      const bad = (m) => new EngineError('bad_did_update', m, 400);
      try { checkVersion(version, { expectRevokedEmpty: false }); } catch (e) { throw bad(e.message); }
      const last = hist.versions[hist.versions.length - 1];
      if (version.version !== last.version + 1) throw bad('version must be ' + (last.version + 1));
      if (version.validFrom < last.validFrom) throw bad('validFrom must not be before the previous version');
      const res = resolver.verifyStatement({ jws, payload: { did, ...version }, typ: DID_UPDATE_TYP, signer: did, date: version.validFrom });
      if (!res.ok) throw bad('update signature refused: ' + res.reason);
      hist.versions.push(clone(version));
      save(did, hist);
      return load(did);
    },

    keysAt(did, date) {
      if (typeof did === 'string' && did.startsWith(DID_KEY)) {
        try { return [{ kid: kidForDidKey(did), publicKey: publicKeyFromDidKey(did) }]; } catch { return []; }
      }
      if (!isIsoDate(date)) return [];
      const hist = load(did);
      if (!hist) return [];
      let inForce = null;
      for (const v of hist.versions) if (v.validFrom <= date) inForce = v;
      if (!inForce) return [];
      const revoked = new Set();
      for (const v of hist.versions) for (const r of v.revoked) if (r.from <= date) revoked.add(r.id);
      return inForce.keys.filter((k) => !revoked.has(k.id)).map((k) => ({ kid: did + k.id, publicKey: rawFromMultibase(k.publicKeyMultibase) }));
    },

    verifyStatement({ jws, payload, typ, signer, date }) {
      let parsed;
      try { parsed = parseJws(jws); } catch { return { ok: false, reason: 'bad_jws' }; }
      const { header } = parsed;
      if (typeof signer !== 'string' || !header.kid.startsWith(signer + '#')) return { ok: false, reason: 'kid_mismatch' };
      if (header.typ !== typ) return { ok: false, reason: 'wrong_type' };
      let key;
      try { key = resolver.keysAt(signer, date).find((k) => k.kid === header.kid); } catch { key = undefined; } // a damaged or refused record is "no valid key", never an exception
      if (!key) return { ok: false, reason: 'key_not_valid' };
      if (!verifyJws({ jws, payload, typ, publicKey: key.publicKey })) return { ok: false, reason: 'bad_signature' };
      return { ok: true, kid: key.kid };
    },
  };
  return resolver;
}
