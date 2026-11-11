import { describe, it, expect } from 'vitest';
import { sign as edSign, randomBytes } from 'node:crypto';
import {
  b64u, fromB64u, base58btcEncode, base58btcDecode, generateKeyPair, keyPairFromSeed, exportPrivateKey, importPrivateKey, publicKeyOf,
  didKeyFromPublicKey, publicKeyFromDidKey, isSmallOrderKey, isIsoDate, kidForDidKey, jwsHeader, signJws, parseJws, verifyJws, makeSigner, createResolver,
} from '../src/keys.mjs';
import { canonical } from '../src/core.mjs';

const hex = (u) => Buffer.from(u).toString('hex');
const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const SEED = unhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const PUB = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const DID = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
const enc = new TextEncoder();

describe('encodings', () => {
  it('base64url round trips 200 random arrays and rejects bad input', () => {
    for (let i = 0; i < 200; i++) {
      const b = new Uint8Array(randomBytes(i % 70));
      expect(fromB64u(b64u(b))).toEqual(b);
    }
    for (const bad of ['a+b', 'a/b', 'ab=', 'a b', 'a', 'QQ==', 'QR']) expect(() => fromB64u(bad)).toThrow();
    expect(() => fromB64u(5)).toThrow();
  });
  it('base58btc round trips 200 random arrays, with leading zeros', () => {
    for (let i = 0; i < 200; i++) {
      const b = new Uint8Array(randomBytes(i % 50));
      b.fill(0, 0, i % 4);
      expect(base58btcDecode(base58btcEncode(b))).toEqual(b);
    }
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe('112');
    expect(base58btcEncode(new Uint8Array([]))).toBe('');
    expect(base58btcEncode(enc.encode('Hello World!'))).toBe('2NEpo7TZRRrLZSi2U');
    expect(() => base58btcDecode('0OIl')).toThrow();
  });
});

describe('keys and did:key', () => {
  it('RFC 8032 test 1 key and signature', () => {
    const kp = keyPairFromSeed(SEED);
    expect(hex(kp.publicKey)).toBe(PUB);
    expect(hex(edSign(null, Buffer.alloc(0), kp.privateKey))).toBe('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  });
  it('did:key of the RFC key, computed independently', () => {
    // independent: multicodec bytes ed 01 + key, base58btc by plain BigInt long division
    const bytes = Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(PUB, 'hex')]);
    const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let n = BigInt('0x' + bytes.toString('hex')), s = '';
    while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
    expect('did:key:z' + s).toBe(DID);
    expect(didKeyFromPublicKey(unhex(PUB))).toBe(DID);
    expect(hex(publicKeyFromDidKey(DID))).toBe(PUB);
    expect(kidForDidKey(DID)).toBe(DID + '#' + DID.slice(8));
  });
  it('refuses malformed did:key', () => {
    expect(() => publicKeyFromDidKey('did:web:x')).toThrow();
    expect(() => publicKeyFromDidKey('did:key:abc')).toThrow();
    expect(() => publicKeyFromDidKey('did:key:z' + base58btcEncode(Uint8Array.from([0xec, 0x01, ...new Uint8Array(32)])))).toThrow();
    expect(() => publicKeyFromDidKey('did:key:z' + base58btcEncode(Uint8Array.from([0xed, 0x01, ...new Uint8Array(31)])))).toThrow();
    expect(() => didKeyFromPublicKey(new Uint8Array(5))).toThrow();
  });
  it('generates, exports and imports', () => {
    const kp = generateKeyPair();
    expect(kp.publicKey.length).toBe(32);
    const back = importPrivateKey(exportPrivateKey(kp.privateKey));
    expect(publicKeyOf(back)).toEqual(kp.publicKey);
    expect(() => keyPairFromSeed(new Uint8Array(31))).toThrow();
    expect(keyPairFromSeed(SEED).publicKey).toEqual(keyPairFromSeed(SEED).publicKey);
  });
});

describe('JWS', () => {
  const kp = keyPairFromSeed(SEED);
  const kid = kidForDidKey(DID);
  const payload = { b: 2, a: [1, 'x'] };
  const typ = 'sanad-test+jws';
  const jws = signJws({ typ, kid, payload, privateKey: kp.privateKey });
  const forge = (header, sigPart) => b64u(enc.encode(header)) + '..' + sigPart;
  const sigOf = jws.split('.')[2];

  it('has the detached shape and a canonical header', () => {
    const parts = jws.split('.');
    expect(parts.length).toBe(3); expect(parts[1]).toBe('');
    expect(Buffer.from(parts[0], 'base64url').toString()).toBe(jwsHeader(typ, kid));
    expect(jwsHeader(typ, kid)).toBe(`{"alg":"EdDSA","kid":${JSON.stringify(kid)},"typ":"${typ}"}`);
  });
  it('round trips, independent of key order in the payload', () => {
    expect(verifyJws({ jws, payload, typ, publicKey: kp.publicKey })).toBe(true);
    expect(verifyJws({ jws, payload: { a: [1, 'x'], b: 2 }, typ, publicKey: kp.publicKey })).toBe(true);
    const p = parseJws(jws);
    expect(p.header).toEqual({ alg: 'EdDSA', kid, typ });
    expect(p.signature.length).toBe(64);
  });
  it('refuses wrong key, tampered payload, typ mismatch', () => {
    expect(verifyJws({ jws, payload, typ, publicKey: generateKeyPair().publicKey })).toBe(false);
    expect(verifyJws({ jws, payload: { ...payload, a: [] }, typ, publicKey: kp.publicKey })).toBe(false);
    expect(verifyJws({ jws, payload, typ: 'other+jws', publicKey: kp.publicKey })).toBe(false);
  });
  it('refuses alg none, extra header member, missing member, non-canonical header', () => {
    expect(verifyJws({ jws: forge(canonical({ alg: 'none', kid, typ }), sigOf), payload, typ, publicKey: kp.publicKey })).toBe(false);
    expect(() => parseJws(forge(canonical({ alg: 'none', kid, typ }), sigOf))).toThrow();
    expect(() => parseJws(forge(canonical({ alg: 'EdDSA', kid, typ, extra: 1 }), sigOf))).toThrow();
    expect(() => parseJws(forge(canonical({ alg: 'EdDSA', typ }), sigOf))).toThrow();
    expect(() => parseJws(forge(`{"typ":"${typ}","kid":${JSON.stringify(kid)},"alg":"EdDSA"}`, sigOf))).toThrow();
    expect(() => parseJws(forge(`{ "alg":"EdDSA","kid":${JSON.stringify(kid)},"typ":"${typ}"}`, sigOf))).toThrow();
    expect(() => parseJws(forge('[]', sigOf))).toThrow();
    expect(() => parseJws(forge('null', sigOf))).toThrow();
  });
  it('refuses attached payload, wrong part count, bad signature length and encoding', () => {
    const [h, , s] = jws.split('.');
    const attached = h + '.' + b64u(enc.encode(canonical(payload))) + '.' + s;
    expect(() => parseJws(attached)).toThrow();
    expect(verifyJws({ jws: attached, payload, typ, publicKey: kp.publicKey })).toBe(false);
    expect(() => parseJws(h + '.' + s)).toThrow();
    expect(() => parseJws(h + '..' + s + '.x')).toThrow();
    expect(() => parseJws(h + '..' + b64u(new Uint8Array(63)))).toThrow();
    expect(() => parseJws(h + '..' + s + '=')).toThrow();
    expect(() => parseJws(42)).toThrow();
    expect(verifyJws({ jws: 42, payload, typ, publicKey: kp.publicKey })).toBe(false);
    expect(verifyJws({ jws, payload, typ, publicKey: new Uint8Array(3) })).toBe(false);
  });
  it('makeSigner defaults to the did:key', () => {
    const s = makeSigner(kp.privateKey);
    expect(s.did).toBe(DID); expect(s.kid).toBe(kidForDidKey(DID)); expect(s.publicKey).toEqual(kp.publicKey);
    expect(verifyJws({ jws: s.sign(typ, payload), payload, typ, publicKey: kp.publicKey })).toBe(true);
    const w = makeSigner(kp.privateKey, 'did:web:example.org');
    expect(w.did).toBe('did:web:example.org'); expect(w.kid.startsWith('did:web:example.org#')).toBe(true);
  });
});

describe('resolver', () => {
  const k1 = generateKeyPair(), k2 = generateKeyPair(), k3 = generateKeyPair();
  const DIDW = 'did:web:example.org';
  const mb = (k) => 'z' + base58btcEncode(k.publicKey);
  const doc = () => ({ id: DIDW, versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: mb(k1) }], revoked: [] }] });
  const v2 = { version: 2, validFrom: '2026-06-01', keys: [{ id: '#k2', publicKeyMultibase: mb(k2) }], revoked: [{ id: '#k1', from: '2026-06-01' }] };
  const T = 'sanad-did-update+jws';
  const signUpdate = (k, kid, v) => signJws({ typ: T, kid, payload: { did: DIDW, ...v }, privateKey: k.privateKey });

  it('registers and refuses bad or duplicate documents', () => {
    const r = createResolver();
    expect(r.get(DIDW)).toBe(null);
    r.register(doc());
    expect(r.get(DIDW).versions.length).toBe(1);
    expect(() => r.register(doc())).toThrow(expect.objectContaining({ code: 'did_exists' }));
    const bad = (d) => expect(() => createResolver().register(d)).toThrow(expect.objectContaining({ code: 'bad_did_document' }));
    bad(null); bad({}); bad({ ...doc(), extra: 1 }); bad({ id: DID, versions: doc().versions }); bad({ id: 'nope', versions: doc().versions });
    bad({ id: DIDW, versions: [] });
    const d = doc(); d.versions[0].version = 2; bad(d);
    const e = doc(); e.versions[0].validFrom = '2026-13-01'; bad(e);
    const f = doc(); f.versions[0].keys[0].publicKeyMultibase = 'zabc'; bad(f);
    const g = doc(); g.versions[0].revoked = [{ id: '#k1', from: '2026-02-01' }]; bad(g);
    const h = doc(); h.versions[0].keys = []; bad(h);
  });
  it('rotation: k1 before, k2 after; revocation applies from its date', () => {
    const r = createResolver(); r.register(doc());
    r.update(DIDW, v2, signUpdate(k1, DIDW + '#k1', v2));
    const ids = (d) => r.keysAt(DIDW, d).map((k) => k.kid);
    expect(ids('2025-12-31')).toEqual([]);
    expect(ids('2026-01-01')).toEqual([DIDW + '#k1']);
    expect(ids('2026-05-31')).toEqual([DIDW + '#k1']);
    expect(ids('2026-06-01')).toEqual([DIDW + '#k2']);
    expect(ids('2027-01-01')).toEqual([DIDW + '#k2']);
    expect(r.keysAt(DIDW, 'garbage')).toEqual([]);
    expect(r.keysAt('did:web:unknown', '2026-02-02')).toEqual([]);
    expect(r.get(DIDW).versions.length).toBe(2);

    const stmt = { n: 1 }, typ = 'sanad-attestation+jws';
    const s1 = signJws({ typ, kid: DIDW + '#k1', payload: stmt, privateKey: k1.privateKey });
    const s2 = signJws({ typ, kid: DIDW + '#k2', payload: stmt, privateKey: k2.privateKey });
    const vs = (jws, date, t = typ, signer = DIDW) => r.verifyStatement({ jws, payload: stmt, typ: t, signer, date });
    expect(vs(s1, '2026-03-01')).toMatchObject({ ok: true, kid: DIDW + '#k1' });
    expect(vs(s1, '2026-06-01')).toEqual({ ok: false, reason: 'key_not_valid' });
    expect(vs(s2, '2026-05-31')).toEqual({ ok: false, reason: 'key_not_valid' });
    expect(vs(s2, '2026-06-02').ok).toBe(true);
    expect(vs(s1, '2026-03-01', 'other').reason).toBe('wrong_type');
    expect(vs(s1, '2026-03-01', typ, 'did:web:other').reason).toBe('kid_mismatch');
    expect(vs(s1, '2026-03-01', typ, 'did:web:example').reason).toBe('kid_mismatch');
    expect(vs('junk', '2026-03-01').reason).toBe('bad_jws');
    const forged = signJws({ typ, kid: DIDW + '#k1', payload: stmt, privateKey: k3.privateKey });
    expect(vs(forged, '2026-03-01').reason).toBe('bad_signature');
  });
  it('a later revocation date makes the key invalid only from that date', () => {
    const r = createResolver(); r.register(doc());
    const v = { version: 2, validFrom: '2026-02-01', keys: [{ id: '#k1', publicKeyMultibase: mb(k1) }, { id: '#k2', publicKeyMultibase: mb(k2) }], revoked: [{ id: '#k1', from: '2026-03-01' }] };
    r.update(DIDW, v, signUpdate(k1, DIDW + '#k1', v));
    expect(r.keysAt(DIDW, '2026-02-15').map((k) => k.kid)).toEqual([DIDW + '#k1', DIDW + '#k2']);
    expect(r.keysAt(DIDW, '2026-03-01').map((k) => k.kid)).toEqual([DIDW + '#k2']);
  });
  it('refuses bad updates', () => {
    const r = createResolver(); r.register(doc());
    const code = (fn, c) => expect(fn).toThrow(expect.objectContaining({ code: c }));
    code(() => r.update('did:web:nobody', v2, 'x'), 'did_unknown');
    code(() => r.update(DIDW, v2, signUpdate(k3, DIDW + '#k1', v2)), 'bad_did_update');       // key not valid (wrong signature)
    code(() => r.update(DIDW, v2, signUpdate(k2, DIDW + '#k2', v2)), 'bad_did_update');       // k2 not yet valid
    code(() => r.update(DIDW, v2, 'junk'), 'bad_did_update');
    code(() => r.update(DIDW, { ...v2, version: 3 }, signUpdate(k1, DIDW + '#k1', { ...v2, version: 3 })), 'bad_did_update');
    const early = { ...v2, validFrom: '2025-12-31' };
    code(() => r.update(DIDW, early, signUpdate(k1, DIDW + '#k1', early)), 'bad_did_update');
    const extra = { ...v2, more: 1 };
    code(() => r.update(DIDW, extra, signUpdate(k1, DIDW + '#k1', extra)), 'bad_did_update');
    code(() => r.update(DIDW, v2, signJws({ typ: 'sanad-commit+jws', kid: DIDW + '#k1', payload: { did: DIDW, ...v2 }, privateKey: k1.privateKey })), 'bad_did_update');
    expect(r.get(DIDW).versions.length).toBe(1);
  });
  it('a revoked key cannot sign an update on or after its revocation date', () => {
    const r = createResolver(); r.register(doc());
    r.update(DIDW, v2, signUpdate(k1, DIDW + '#k1', v2));
    const v3 = { version: 3, validFrom: '2026-07-01', keys: [{ id: '#k3', publicKeyMultibase: mb(k3) }], revoked: [{ id: '#k2', from: '2026-07-01' }] };
    expect(() => r.update(DIDW, v3, signUpdate(k1, DIDW + '#k1', v3))).toThrow(expect.objectContaining({ code: 'bad_did_update' }));
    r.update(DIDW, v3, signUpdate(k2, DIDW + '#k2', v3));
    expect(r.keysAt(DIDW, '2026-07-02').map((k) => k.kid)).toEqual([DIDW + '#k3']);
  });
  it('resolves did:key always and verifies with it', () => {
    const r = createResolver();
    const s = makeSigner(k1.privateKey);
    expect(r.keysAt(s.did, '1999-01-01')).toEqual([{ kid: s.kid, publicKey: k1.publicKey }]);
    expect(r.keysAt(s.did, 'whatever').length).toBe(1);
    const p = { x: 1 };
    expect(r.verifyStatement({ jws: s.sign('t+jws', p), payload: p, typ: 't+jws', signer: s.did, date: '2026-01-01' })).toMatchObject({ ok: true, kid: s.kid });
    expect(() => r.register({ id: s.did, versions: [] })).toThrow(expect.objectContaining({ code: 'bad_did_document' }));
  });
  it('uses a store when given', () => {
    const m = new Map(); const calls = [];
    const store = { get: (c, id) => { calls.push(['get', c]); return m.get(c + '/' + id) ?? null; }, put: (c, id, v) => { calls.push(['put', c]); m.set(c + '/' + id, v); } };
    const r = createResolver({ store }); r.register(doc());
    expect(m.has('dids/' + DIDW)).toBe(true);
    expect(createResolver({ store }).keysAt(DIDW, '2026-02-01').length).toBe(1);
    expect(calls.every(([, c]) => c === 'dids')).toBe(true);
  });
});

describe('review fixes', () => {
  const kp = keyPairFromSeed(SEED);
  const kid = kidForDidKey(DID);
  const typ = 'sanad-test+jws';
  const payload = { a: 1 };
  it('refuses a header with a byte-order mark although it was signed', () => {
    const hdr = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(jwsHeader(typ, kid))]);
    const hb = b64u(hdr);
    const input = hb + '.' + b64u(enc.encode(canonical(payload)));
    const jws = hb + '..' + b64u(edSign(null, Buffer.from(input), kp.privateKey));
    expect(() => parseJws(jws)).toThrow();
    expect(verifyJws({ jws, payload, typ, publicKey: kp.publicKey })).toBe(false);
  });
  it('refuses a signature whose S is raised by the group order', () => {
    const jws = signJws({ typ, kid, payload, privateKey: kp.privateKey });
    const [h, , s] = jws.split('.');
    const sig = new Uint8Array(fromB64u(s));
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let S = 0n; for (let i = 31; i >= 0; i--) S = (S << 8n) | BigInt(sig[32 + i]);
    let t = S + L; for (let i = 0; i < 32; i++) { sig[32 + i] = Number(t & 255n); t >>= 8n; }
    expect(verifyJws({ jws: h + '..' + b64u(sig), payload, typ, publicKey: kp.publicKey })).toBe(false);
  });
  it('refuses small-order keys, which would verify one signature over any message', () => {
    const identity = new Uint8Array(32); identity[0] = 1;
    const zeroY = new Uint8Array(32);
    const minusOne = Uint8Array.from(unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'));
    const universal = new Uint8Array(64); universal[0] = 1; // R = identity, S = 0
    const jws = b64u(enc.encode(jwsHeader(typ, 'x#k'))) + '..' + b64u(universal);
    for (const k of [identity, zeroY, minusOne]) {
      expect(isSmallOrderKey(k)).toBe(true);
      expect(verifyJws({ jws, payload: { any: 'thing' }, typ, publicKey: k })).toBe(false);
      expect(() => publicKeyFromDidKey(didKeyFromPublicKey(k))).toThrow();
    }
    expect(isSmallOrderKey(kp.publicKey)).toBe(false);
    expect(isSmallOrderKey(generateKeyPair().publicKey)).toBe(false);
    const r = createResolver();
    const doc = { id: 'did:web:a.example', versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: 'z' + base58btcEncode(identity) }], revoked: [] }] };
    expect(() => r.register(doc)).toThrow(/usable/);
    expect(r.verifyStatement({ jws, payload: {}, typ, signer: 'did:key:z' + base58btcEncode(Uint8Array.from([0xed, 0x01, ...identity])), date: '2026-02-01' }).ok).toBe(false);
  });
  it('refuses overlong did:key and multibase input without long computation', () => {
    expect(() => publicKeyFromDidKey('did:key:z' + '2'.repeat(100000))).toThrow();
    const r = createResolver();
    const doc = { id: 'did:web:b.example', versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: 'z' + '2'.repeat(100000) }], revoked: [] }] };
    expect(() => r.register(doc)).toThrow();
  });
  it('isIsoDate agrees with the core on years below 100', () => {
    expect(isIsoDate('0050-01-01')).toBe(false);
    expect(isIsoDate('0100-01-01')).toBe(true);
    expect(isIsoDate('2026-02-29')).toBe(false);
  });
  it('verifyStatement returns a result, not an exception, when the store throws', () => {
    const store = { get() { throw new Error('damaged'); }, put() {} };
    const r = createResolver({ store });
    const jws = signJws({ typ, kid: 'did:web:c.example#k1', payload, privateKey: kp.privateKey });
    expect(r.verifyStatement({ jws, payload, typ, signer: 'did:web:c.example', date: '2026-02-01' })).toEqual({ ok: false, reason: 'key_not_valid' });
  });
});
