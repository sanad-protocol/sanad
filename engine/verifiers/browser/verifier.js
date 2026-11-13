// Sanad browser verifier: no network, no libraries. Verifies an exported static directory (SPEC 6.1 and 11) with WebCrypto (SHA-256, Ed25519) and the
// recognition core (reference/dist, inlined by build.mjs as `SANAD_CORE`). Exposes globalThis.SanadVerifier = { verifyTree, readZip, DEFAULT_POLICY }.
// A passing report records what was signed and logged, not that the attestors were honest.
(function (globalThis) {
  'use strict';
  const core = SANAD_CORE;
  const enc = new TextEncoder(), dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const HEX64 = /^[0-9a-f]{64}$/;
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const isStr = (v) => typeof v === 'string';
  const exactly = (o, names) => isObj(o) && Object.keys(o).sort().join('\u0000') === [...names].sort().join('\u0000');
  const same = (a, b) => core.canonical(a) === core.canonical(b);
  const day = (iso) => String(iso).slice(0, 10);
  const hex = (u8) => Array.from(u8, (x) => x.toString(16).padStart(2, '0')).join('');
  const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const DEFAULT_POLICY = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8, asOf: new Date().toISOString().slice(0, 10) };

  // ---- encodings
  const b64uEnc = (u8) => { let s = ''; for (const x of u8) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  function b64uDec(s) {
    if (!isStr(s) || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('not base64url');
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    if (b64uEnc(out) !== s) throw new Error('not canonical base64url');
    return out;
  }
  const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58dec(str) {
    let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++;
    let n = 0n; for (const c of str) { const v = ALPHA.indexOf(c); if (v < 0) throw new Error('bad base58'); n = n * 58n + BigInt(v); }
    let h = n === 0n ? '' : n.toString(16); if (h.length % 2) h = '0' + h;
    return Uint8Array.from([...new Uint8Array(zeros), ...unhex(h)]);
  }
  function b58enc(bytes) {
    let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    let n = 0n; for (const x of bytes) n = (n << 8n) | BigInt(x);
    let s = ''; while (n > 0n) { s = ALPHA[Number(n % 58n)] + s; n /= 58n; }
    return '1'.repeat(zeros) + s;
  }

  // ---- Ed25519 strictness (S < L, no small-order keys) around WebCrypto's verify
  const P = 2n ** 255n - 19n;
  const modPow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
  const inv = (a) => modPow(((a % P) + P) % P, P - 2n, P);
  const D = ((P - 121665n * inv(121666n) % P) % P + P) % P;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const le = (u8) => { let n = 0n; for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]); return n; };
  function smallOrder(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) return true;
    let y = le(raw) & ((1n << 255n) - 1n); y %= P;
    const y2 = y * y % P, u = (y2 - 1n + P) % P, v = (D * y2 + 1n) % P, t = u * inv(v) % P;
    let x = modPow(t, (P + 3n) / 8n, P);
    if (x * x % P !== t) x = x * modPow(2n, (P - 1n) / 4n, P) % P;
    if (x * x % P !== t) return true;
    const add = (a, b) => { const k = D * a[0] % P * a[1] % P * b[0] % P * b[1] % P; return [(a[0] * b[1] + b[0] * a[1]) % P * inv(1n + k) % P, (a[1] * b[1] + a[0] * b[0]) % P * inv(1n - k) % P]; };
    let q = [x, y]; for (let i = 0; i < 3; i++) q = add(q, q);
    return q[0] === 0n && q[1] === 1n;
  }
  const keyCache = new Map();
  async function edVerify(pub, msg, sig) {
    if (sig.length !== 64 || le(sig.slice(32)) >= L || smallOrder(pub)) return false;
    try {
      let k = keyCache.get(hex(pub));
      if (!k) { k = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']); keyCache.set(hex(pub), k); }
      return await crypto.subtle.verify({ name: 'Ed25519' }, k, sig, msg);
    } catch { return false; }
  }

  // ---- DIDs, JWS
  const isoDate = (s) => { if (!isStr(s) || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false; const d = new Date(s + 'T00:00:00Z'); return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s && Number(s.slice(0, 4)) >= 100; };
  const TS = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-](\d\d):(\d\d))$/;
  function isoTime(ts) {
    const m = isStr(ts) ? TS.exec(ts) : null; if (!m) return false;
    const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
    if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return false;
    if (m[9] !== undefined && (Number(m[9]) > 23 || Number(m[10]) > 59)) return false;
    if (d > new Date(Date.UTC(2000 + (y % 400), mo, 0)).getUTCDate()) return false;
    return !Number.isNaN(Date.parse(ts));
  }
  function didKeyPublic(did) {
    if (!isStr(did) || !did.startsWith('did:key:z') || did.length > 80) throw new Error('not did:key');
    const b = b58dec(did.slice(9));
    if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new Error('not an Ed25519 did:key');
    const k = b.slice(2); if (smallOrder(k)) throw new Error('unusable key'); return k;
  }
  function multibaseKey(mb) { if (!isStr(mb) || mb[0] !== 'z' || mb.length > 80) throw new Error('bad multibase'); const r = b58dec(mb.slice(1)); if (r.length !== 32 || smallOrder(r)) throw new Error('bad key'); return r; }
  function parseJws(jws) {
    if (!isStr(jws)) throw new Error('JWS must be a string');
    const p = jws.split('.'); if (p.length !== 3 || p[1] !== '') throw new Error('JWS shape');
    const hb = b64uDec(p[0]); const text = dec.decode(hb); const header = JSON.parse(text);
    if (!isObj(header) || Object.keys(header).sort().join() !== 'alg,kid,typ' || header.alg !== 'EdDSA' || !isStr(header.kid) || !isStr(header.typ) || text !== core.canonical(header)) throw new Error('header');
    return { header, headerB64: p[0], signature: b64uDec(p[2]) };
  }
  // keys come from DID histories found in the credential/directory (untrusted: reported through `used`) or from did:key
  function makeResolver(histories, used) {
    const map = new Map(); for (const d of histories) if (isObj(d) && isStr(d.id) && Array.isArray(d.versions)) map.set(d.id, d);
    const keyAt = (did, kid, date) => {
      if (did.startsWith('did:key:')) { try { return kid === did + '#' + did.slice(8) ? didKeyPublic(did) : null; } catch { return null; } }
      if (!isoDate(date) || !kid.startsWith(did + '#')) return null;
      const h = map.get(did); if (!h) return null;
      let inForce = null; for (const v of h.versions) if (isObj(v) && v.validFrom <= date) inForce = v;
      if (!inForce) return null;
      const frag = kid.slice(did.length); const entry = (inForce.keys || []).find((k) => k.id === frag); if (!entry) return null;
      for (const v of h.versions) for (const r of (v.revoked || [])) if (r.id === frag && r.from <= date) return null;
      try { return { key: multibaseKey(entry.publicKeyMultibase), mb: entry.publicKeyMultibase }; } catch { return null; }
    };
    return {
      async verifyStatement({ jws, payload, typ, signer, date }) {
        let pj; try { pj = parseJws(jws); } catch { return { ok: false, reason: 'bad_jws' }; }
        if (!isStr(signer) || !pj.header.kid.startsWith(signer + '#')) return { ok: false, reason: 'kid_mismatch' };
        if (pj.header.typ !== typ) return { ok: false, reason: 'wrong_type' };
        const k = keyAt(signer, pj.header.kid, date); if (!k) return { ok: false, reason: 'key_not_valid' };
        const raw = k.key ?? k;
        const input = enc.encode(pj.headerB64 + '.' + b64uEnc(enc.encode(core.canonical(payload))));
        if (!(await edVerify(raw, input, pj.signature))) return { ok: false, reason: 'bad_signature' };
        if (!signer.startsWith('did:key:') && used) { if (!used.has(signer)) used.set(signer, new Set()); used.get(signer).add(k.mb); }
        return { ok: true, kid: pj.header.kid };
      },
    };
  }

  // ---- Merkle (RFC 9162)
  const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
  const leafHash = async (text) => hex(await sha256(cat(Uint8Array.of(0), enc.encode(text))));
  const nodeHash = async (l, r) => hex(await sha256(cat(Uint8Array.of(1), unhex(l), unhex(r))));
  const okHex = (h) => isStr(h) && HEX64.test(h);
  const isSize = (x) => Number.isSafeInteger(x) && x >= 0;
  const half = (x) => Math.floor(x / 2);
  async function verifyInclusion({ leafHash: lh, index, size, proof, root }) {
    try {
      if (!okHex(lh) || !okHex(root) || !Array.isArray(proof) || !proof.every(okHex) || !isSize(index) || !isSize(size) || index >= size) return false;
      let fn = index, sn = size - 1, r = lh;
      for (const p of proof) {
        if (sn === 0) return false;
        if (fn % 2 === 1 || fn === sn) { r = await nodeHash(p, r); if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); } } else r = await nodeHash(r, p);
        fn = half(fn); sn = half(sn);
      }
      return sn === 0 && r === root;
    } catch { return false; }
  }
  async function verifyConsistency({ m, n, proof, rootM, rootN }) {
    try {
      if (!isSize(m) || !isSize(n) || !okHex(rootM) || !okHex(rootN) || !Array.isArray(proof) || !proof.every(okHex) || m < 1 || m > n) return false;
      if (m === n) return proof.length === 0 && rootM === rootN;
      const path = (m & (m - 1)) === 0 ? [rootM, ...proof] : [...proof];
      if (path.length === 0) return false;
      let fn = m - 1, sn = n - 1; while (fn % 2 === 1) { fn = half(fn); sn = half(sn); }
      let fr = path[0], sr = path[0];
      for (const c of path.slice(1)) {
        if (sn === 0) return false;
        if (fn % 2 === 1 || fn === sn) { fr = await nodeHash(c, fr); sr = await nodeHash(c, sr); if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); } } else sr = await nodeHash(sr, c);
        fn = half(fn); sn = half(sn);
      }
      return sn === 0 && fr === rootM && sr === rootN;
    } catch { return false; }
  }
  async function checkpointOk(cp, res, logKey) {
    try {
      const p = cp?.payload; if (!isObj(p) || !isStr(cp.jws) || Object.keys(p).sort().join() !== 'logId,rootHash,size,timestamp') return false;
      if (!isStr(p.logId) || !isSize(p.size) || !okHex(p.rootHash) || !isoTime(p.timestamp)) return false;
      return (await res.verifyStatement({ jws: cp.jws, payload: p, typ: 'sanad-checkpoint+jws', signer: logKey, date: day(p.timestamp) })).ok;
    } catch { return false; }
  }

  // ---- sitting evidence (SPEC 3.3)
  const IDENT = ['A0', 'A1', 'A2'];
  function sittingProblems(b) {
    const p = [];
    const hx = (k) => { if (k in b && !(isStr(b[k]) && HEX64.test(b[k]))) p.push(k + ' must be 64 lower-case hex characters'); };
    if ('sittingId' in b && !(isStr(b.sittingId) && /^[A-Za-z0-9._:-]{1,200}$/.test(b.sittingId))) p.push('sittingId form');
    for (const k of ['paperFingerprint', 'strokeLogHead', 'recordingSha256', 'recordingCipherSha256']) hx(k);
    if ('recordingCipherSha256' in b && !('recordingSha256' in b)) p.push('recordingCipherSha256 needs recordingSha256');
    if ('recordingBytes' in b && !(Number.isSafeInteger(b.recordingBytes) && b.recordingBytes > 0)) p.push('recordingBytes must be a positive integer');
    if ('recordingSha256' in b && !('recordingBytes' in b)) p.push('recordingSha256 needs recordingBytes');
    if ('recordingBytes' in b && !('recordingSha256' in b)) p.push('recordingBytes without recordingSha256');
    if ('identityAssurance' in b) {
      const ia = b.identityAssurance;
      if (!exactly(ia, ['level', 'method', 'checkedBy', 'date', 'candidateKey', 'signature'])) p.push('identityAssurance members');
      else {
        if (!IDENT.includes(ia.level)) p.push('identityAssurance.level');
        if (!(isStr(ia.method) && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(ia.method))) p.push('identityAssurance.method');
        if (!(isStr(ia.checkedBy) && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(ia.checkedBy) && ia.checkedBy.length <= 200)) p.push('identityAssurance.checkedBy');
        if (!isoDate(ia.date)) p.push('identityAssurance.date');
        try { multibaseKey(ia.candidateKey); } catch { p.push('identityAssurance.candidateKey'); }
        if (!isStr(ia.signature) || !ia.signature || ia.signature.length > 400) p.push('identityAssurance.signature');
        if (!('sittingId' in b)) p.push('identityAssurance needs sittingId');
      }
    }
    if ('publication' in b) {
      const pb = b.publication;
      if (!isObj(pb) || !Object.keys(pb).every((k) => ['scope', 'url', 'date'].includes(k)) || !('scope' in pb) || !('date' in pb)) p.push('publication members');
      else {
        if (!['hashes', 'bundle'].includes(pb.scope)) p.push('publication.scope');
        if (!isoDate(pb.date)) p.push('publication.date');
        if ('url' in pb && !(isStr(pb.url) && /^https?:\/\/[^\s]{1,300}$/.test(pb.url))) p.push('publication.url');
      }
    }
    return p;
  }

  // ---- Bitstring Status List
  async function gunzip(u8) { const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip')); return new Uint8Array(await new Response(s).arrayBuffer()); }
  async function checkStatus(cred, lists, nowMs, res) {
    const e = cred.credentialStatus;
    if (!exactly(e, ['id', 'type', 'statusPurpose', 'statusListIndex', 'statusListCredential']) || e.type !== 'BitstringStatusListEntry' || e.statusPurpose !== 'revocation' || !/^(0|[1-9]\d{0,8})$/.test(String(e.statusListIndex)) || !/^https?:\/\/\S+$/.test(String(e.statusListCredential)) || e.id !== e.statusListCredential + '#' + e.statusListIndex) return { ok: false, detail: 'credentialStatus malformed' };
    const list = lists.find((l) => isObj(l) && l.id === e.statusListCredential);
    if (!list) return { ok: false, detail: 'the status list ' + e.statusListCredential + ' was not supplied' };
    try {
      const { proof, ...body } = list;
      if (!isObj(proof) || proof.type !== 'SanadDetachedJws') return { ok: false, detail: 'the status list has no Sanad proof' };
      if (list.issuer !== cred.issuer) return { ok: false, detail: 'the status list is not issued by the credential\'s issuer' };
      if (!same(list.type, ['VerifiableCredential', 'BitstringStatusListCredential']) || list.credentialSubject?.type !== 'BitstringStatusList' || list.credentialSubject?.statusPurpose !== 'revocation') return { ok: false, detail: 'not a revocation status list' };
      const r = await res.verifyStatement({ jws: proof.jws, payload: body, typ: 'sanad-status-list+jws', signer: list.issuer, date: day(list.validFrom) });
      if (!r.ok || r.kid !== proof.verificationMethod || proof.created !== list.validFrom) return { ok: false, detail: 'the status list signature is refused' };
      if (!(Date.parse(list.validFrom) <= nowMs)) return { ok: false, detail: 'the status list is dated after the evaluation time' };
      if (list.validUntil !== undefined && !(nowMs <= Date.parse(list.validUntil))) return { ok: false, detail: 'the status list expired at ' + list.validUntil };
      const enc2 = list.credentialSubject.encodedList; if (!isStr(enc2) || enc2[0] !== 'u') return { ok: false, detail: 'encodedList must start with u' };
      const bits = await gunzip(b64uDec(enc2.slice(1)));
      if (bits.length * 8 < 131072) return { ok: false, detail: 'the list is shorter than 131072 bits' };
      const idx = Number(e.statusListIndex); if (idx >= bits.length * 8) return { ok: false, detail: 'statusListIndex is outside the list' };
      const revoked = (bits[idx >> 3] & (0x80 >> (idx % 8))) !== 0;
      return { ok: !revoked, detail: revoked ? 'revoked: bit ' + idx + ' is set' : 'bit ' + idx + ' is clear' };
    } catch (x) { return { ok: false, detail: 'the status list is not usable: ' + (x && x.message) }; }
  }

  // ---- witnesses (SPEC 8.2)
  async function verifyWitnesses(cpBase, logKey, res, cosigned, consistency, trusted) {
    if (!Array.isArray(trusted) || !trusted.length) return { count: 0, witnesses: [], problems: ['no witness is pinned'] };
    const seen = new Set(), problems = [], base = cpBase.payload;
    for (const [i, it] of (Array.isArray(cosigned) ? cosigned : []).entries()) {
      const w = it?.cosignature?.witness; const bad = (m) => problems.push('cosignature ' + i + ': ' + m);
      if (!isObj(it) || !isObj(it.checkpoint) || !isObj(it.cosignature)) { bad('malformed'); continue; }
      if (!trusted.includes(w)) { bad('witness is not pinned'); continue; }
      if (seen.has(w)) continue;
      const cp = it.checkpoint;
      if (!(await checkpointOk(cp, res, logKey))) { bad('checkpoint not signed by the log key'); continue; }
      if (cp.payload.logId !== base.logId) { bad('another log'); continue; }
      const cs = it.cosignature;
      if (!exactly(cs, ['jws', 'witness', 'witnessedAt']) || !isoTime(cs.witnessedAt)) { bad('malformed cosignature'); continue; }
      const st = { type: 'sanad-cosignature', logId: cp.payload.logId, size: cp.payload.size, rootHash: cp.payload.rootHash, timestamp: cp.payload.timestamp, logKey, witness: w, witnessedAt: cs.witnessedAt };
      if (!(await res.verifyStatement({ jws: cs.jws, payload: st, typ: 'sanad-cosignature+jws', signer: w, date: day(cs.witnessedAt) })).ok) { bad('signature refused'); continue; }
      if (cp.payload.size < base.size) { bad('smaller than the credential\'s checkpoint'); continue; }
      if (cp.payload.size === base.size) { if (cp.payload.rootHash !== base.rootHash) { bad('forked'); continue; } }
      else {
        const c = consistency.find((x) => x.m === base.size && x.n === cp.payload.size && x.rootM === base.rootHash && x.rootN === cp.payload.rootHash);
        if (!c || !(await verifyConsistency(c))) { bad('no valid consistency proof'); continue; }
      }
      seen.add(w);
    }
    return { count: seen.size, witnesses: [...seen], problems };
  }

  // ---- ZIP reader (stored and deflate entries) -> Map path -> text
  async function readZip(buf) {
    const u = new Uint8Array(buf), dv = new DataView(u.buffer, u.byteOffset, u.byteLength);
    let e = u.length - 22; while (e >= 0 && dv.getUint32(e, true) !== 0x06054b50) e--;
    if (e < 0) throw new Error('not a zip file');
    const n = dv.getUint16(e + 10, true); let p = dv.getUint32(e + 16, true);
    const out = new Map(); let total = 0;
    for (let i = 0; i < n; i++) {
      if (dv.getUint32(p, true) !== 0x02014b50) throw new Error('bad central directory');
      const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
      const nl = dv.getUint16(p + 28, true), xl = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), lo = dv.getUint32(p + 42, true);
      const name = dec.decode(u.slice(p + 46, p + 46 + nl)); p += 46 + nl + xl + cl;
      if (name.endsWith('/') || name.split('/').some((s) => s === '..')) continue;
      total += usize; if (total > 64 * 1024 * 1024 || out.size > 5000) throw new Error('the archive is larger than a bundle should be');
      const lnl = dv.getUint16(lo + 26, true), lxl = dv.getUint16(lo + 28, true), data = u.slice(lo + 30 + lnl + lxl, lo + 30 + lnl + lxl + csize);
      let bytes;
      if (method === 0) bytes = data;
      else if (method === 8) bytes = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer());
      else throw new Error('unsupported zip method ' + method);
      out.set(name.replace(/^\.\//, ''), dec.decode(bytes));
    }
    return out;
  }

  // ---- the verification
  const TOP = ['@context', 'type', 'id', 'issuer', 'validFrom', 'credentialSubject', 'evidence', 'sanad', 'proof'];
  const ISO_DT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  const KINDS = ['auto', 'sitting', 'artifact', 'peer'];
  const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const bundleHashOf = (b) => core.hashOf({ alg: 'sanad-0.1', skill: b.skill, claimedLevel: b.claimedLevel, subject: b.subject, evidence: [...b.evidence].sort(byId), attestations: [...b.attestations].sort(byId) });

  /**
   * @param {Map<string,string>} files path -> text (from a directory listing or readZip)
   * @param {{ policy?: object, trustedIssuers?: string[], trustedLogKeys?: string[], trustedLogIds?: string[], pinnedKeys?: object, minIdentityLevel?: string, requireWitnesses?: number, trustedWitnesses?: string[], requireStatus?: boolean, statusLists?: object[], bundle?: string, now?: number, allowUnpinned?: boolean }} opts
   */
  async function verifyTree(files, opts = {}) {
    const checks = [], warnings = [];
    const ADD = (name, ok, detail) => checks.push({ name, ok, detail });
    const out = (report) => ({ ok: checks.every((c) => c.ok), checks, warnings, recognition: report ?? null });
    try {
      const dirs = [...new Set([...files.keys()].map((k) => /^(?:.*\/)?bundles\/([0-9a-f]{64})\/credential\.json$/.exec(k)?.[1]).filter(Boolean))];
      const hash = opts.bundle ?? (dirs.length === 1 ? dirs[0] : undefined);
      if (!hash || !dirs.includes(hash)) { ADD('bundle-files', false, dirs.length ? 'several bundles: name one' : 'no bundles/<hash>/credential.json found'); return out(); }
      const full = [...files.keys()].find((k) => k.endsWith('bundles/' + hash + '/credential.json'));
      const prefix = full.slice(0, full.length - ('bundles/' + hash + '/credential.json').length);
      const dir = prefix + 'bundles/' + hash + '/', get = (n) => files.get(dir + n);
      // manifest
      {
        const why = []; let m; try { m = JSON.parse(get('manifest.json') ?? 'null'); } catch { m = null; }
        if (!isObj(m) || m.type !== 'sanad-bundle-manifest' || !isObj(m.files)) why.push('manifest.json missing or malformed');
        else {
          if (m.bundleHash !== hash) why.push('manifest names another bundle hash');
          for (const [n, h] of Object.entries(m.files)) { const t = get(n); if (t === undefined) why.push(n + ' is listed but missing'); else if (hex(await sha256(enc.encode(t))) !== h) why.push(n + ' does not match its SHA-256'); }
          for (const n of ['credential.json', 'evidence.json', 'attestations.json', 'log.json', 'checkpoint.json', 'consistency.json', 'dids.json', 'README.md']) if (!(n in m.files)) why.push(n + ' is required and not listed');
          for (const n of ['witnesses.json', 'status.json']) if (get(n) !== undefined && !(n in m.files)) why.push(n + ' is present but not listed');
          const extra = [...files.keys()].filter((k) => k.startsWith(dir) && k !== dir + 'manifest.json' && !(k.slice(dir.length) in m.files));
          if (extra.length) warnings.push('files not listed in the manifest: ' + extra.map((k) => k.slice(dir.length)).join(', '));
        }
        ADD('bundle-files', why.length === 0, why.length ? why.join('; ') : 'every file matches the manifest');
        if (why.length) return out();
      }
      const cred = JSON.parse(get('credential.json')); const sanad = cred?.sanad;
      if (!isObj(sanad)) { ADD('bundle-consistency', false, 'no sanad member'); return out(); }
      {
        const why = []; if (cred.evidence?.[0]?.bundleHash !== hash) why.push('directory name is not the bundle hash');
        const eq = (n, v) => { let x; try { x = JSON.parse(get(n)); } catch { x = Symbol('bad'); } if (typeof x === 'symbol' || !same(x, v)) why.push(n + ' differs from the credential'); };
        eq('evidence.json', sanad.bundle?.evidence); eq('attestations.json', sanad.bundle?.attestations);
        eq('log.json', { logId: sanad.log?.logId, logKey: sanad.log?.logKey, entries: sanad.log?.entries, proofs: sanad.log?.proofs });
        eq('checkpoint.json', sanad.log?.checkpoint); eq('dids.json', sanad.dids);
        ADD('bundle-consistency', why.length === 0, why.length ? why.join('; ') : 'split files agree with the credential'); if (why.length) return out();
      }
      const used = new Map(), embedded = Array.isArray(sanad.dids) ? sanad.dids : [];
      const res = makeResolver(embedded, used);
      const logKey = sanad.log?.logKey;
      // issuer card
      {
        const t = files.get(prefix + 'issuer.json');
        if (t === undefined) warnings.push('no issuer.json: the issuer card was not checked');
        else {
          const why = [];
          try {
            const card = JSON.parse(t);
            if (!isObj(card) || card.type !== 'sanad-issuer-card') why.push('not an issuer card');
            else {
              if (card.issuer !== cred.issuer) why.push('card issuer differs');
              if (card.logKey !== logKey || card.logId !== sanad.log.logId) why.push('card log differs');
              const { proof, ...body } = card;
              if (!isObj(proof) || proof.type !== 'SanadDetachedJws') why.push('card not signed');
              else {
                const r2 = makeResolver([...(Array.isArray(card.dids) ? card.dids : []), ...embedded], null);
                const r = await r2.verifyStatement({ jws: proof.jws, payload: body, typ: 'sanad-issuer-card+jws', signer: card.issuer, date: day(card.updated) });
                if (!r.ok || r.kid !== proof.verificationMethod) why.push('card signature refused');
              }
            }
          } catch { why.push('issuer.json is not valid JSON'); }
          ADD('issuer-card', why.length === 0, why.length ? why.join('; ') : 'card is signed by the issuer and names its log');
        }
      }
      // consistency proofs
      const consistency = [];
      {
        const why = []; let list = []; try { list = JSON.parse(get('consistency.json') ?? '[]'); } catch { why.push('consistency.json is not JSON'); }
        const cp = sanad.log.checkpoint.payload;
        for (const [i, c] of (Array.isArray(list) ? list : []).entries()) {
          const to = c?.to?.checkpoint;
          const ok = isObj(to) && c.from?.size === cp.size && c.from?.rootHash === cp.rootHash && (await checkpointOk(to, res, logKey)) && to.payload.logId === cp.logId
            && (await verifyConsistency({ m: cp.size, n: to.payload.size, proof: c.proof, rootM: cp.rootHash, rootN: to.payload.rootHash }));
          if (!ok) why.push('entry ' + i + ' is not a valid consistency proof'); else consistency.push({ m: cp.size, n: to.payload.size, rootM: cp.rootHash, rootN: to.payload.rootHash, proof: c.proof });
        }
        ADD('consistency-proofs', why.length === 0, why.length ? why.join('; ') : consistency.length + ' later checkpoint(s) proven to extend the log');
      }

      // shape
      const p = [];
      if (!exactly(cred, TOP) && !exactly(cred, [...TOP, 'credentialStatus'])) p.push('top level members');
      else {
        if (!same(cred['@context'], ['https://www.w3.org/ns/credentials/v2'])) p.push('@context');
        if (!same(cred.type, ['VerifiableCredential', 'SanadCredential'])) p.push('type');
        if (!(isStr(cred.id) && /^urn:uuid:[0-9a-f-]{36}$/.test(cred.id))) p.push('id');
        if (!(isStr(cred.issuer) && cred.issuer.startsWith('did:'))) p.push('issuer');
        if (!(isStr(cred.validFrom) && ISO_DT.test(cred.validFrom) && !Number.isNaN(Date.parse(cred.validFrom)))) p.push('validFrom');
        if (!exactly(cred.credentialSubject, ['id', 'skill', 'claimedLevel'])) p.push('credentialSubject');
        if (!(Array.isArray(cred.evidence) && cred.evidence.length === 1 && exactly(cred.evidence[0], ['type', 'id', 'bundleHash', 'alg']))) p.push('evidence reference');
        if (!exactly(cred.proof, ['type', 'verificationMethod', 'created', 'jws'])) p.push('proof members');
        if (!exactly(sanad, ['bundle', 'template', 'assessment', 'process', 'policy', 'log', 'dids'])) p.push('sanad members');
        else {
          const b = sanad.bundle;
          if (!exactly(b, ['skill', 'claimedLevel', 'subject', 'evidence', 'attestations', 'attestors'])) p.push('bundle members');
          else if (!Array.isArray(b.evidence) || !Array.isArray(b.attestations) || !isObj(b.attestors)) p.push('bundle lists');
          else {
            if (!Number.isInteger(b.claimedLevel) || b.claimedLevel < 0 || b.claimedLevel > 5) p.push('claimedLevel');
            if (b.attestations.length > 200 || b.evidence.length > 200) p.push('too many items');
            b.evidence.forEach((e, i) => { if (!exactly(e, ['id', 'kind', 'date', 'summary', 'body', 'hash']) || !isStr(e.id) || !KINDS.includes(e.kind) || !isStr(e.date) || !isStr(e.summary) || !isObj(e.body) || !isStr(e.hash)) p.push('evidence[' + i + ']'); });
            b.attestations.forEach((a, i) => { if (!exactly(a, ['id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'signature', 'commit', 'nonce', 'prev', 'hash']) || !['id', 'attestor', 'evidence', 'role', 'date', 'signature', 'commit', 'nonce', 'prev', 'hash'].every((k) => isStr(a[k])) || !Number.isInteger(a.level) || typeof a.conflictDeclared !== 'boolean') p.push('attestations[' + i + ']'); });
            if (new Set(b.evidence.map((e) => e.id)).size !== b.evidence.length) p.push('duplicate evidence id');
            if (new Set(b.attestations.map((a) => a.id)).size !== b.attestations.length) p.push('duplicate attestation id');
          }
          const l = sanad.log;
          if (!(exactly(l, ['logId', 'logKey', 'entries', 'proofs', 'checkpoint']) && Array.isArray(l.entries) && Array.isArray(l.proofs) && l.entries.every((e) => exactly(e, ['index', 'leaf'])) && l.proofs.every((e) => exactly(e, ['index', 'size', 'proof'])) && exactly(l.checkpoint, ['payload', 'jws']))) p.push('log members');
          if (!exactly(sanad.template, ['id', 'hash']) || !isStr(sanad.assessment)) p.push('template/assessment');
          if (!Array.isArray(sanad.dids) || !sanad.dids.every((d) => exactly(d, ['id', 'versions']))) p.push('dids');
          const pr = sanad.process;
          if (!isObj(pr) || !['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted'].every((k) => k in pr) || !Object.keys(pr).every((k) => ['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted', 'removed', 'shortfall', 'evidenceAdded'].includes(k))) p.push('process members');
        }
      }
      ADD('shape', p.length === 0, p.length ? p.join('; ') : 'closed member sets everywhere');
      if (p.length) return out();
      const bundle = sanad.bundle;

      { const { proof, ...body } = cred; const r = await res.verifyStatement({ jws: proof.jws, payload: body, typ: 'sanad-credential+jws', signer: cred.issuer, date: day(cred.validFrom) });
        ADD('issuer-proof', r.ok && r.kid === proof.verificationMethod && proof.created === cred.validFrom && proof.type === 'SanadDetachedJws', r.ok ? 'signed by ' + r.kid : 'issuer signature refused: ' + r.reason); }
      { const h = bundleHashOf(bundle), ref = cred.evidence[0], why = [];
        if (h !== ref.bundleHash) why.push('recomputed ' + h + ' differs');
        if (ref.id !== 'urn:sanad:bundle:' + ref.bundleHash) why.push('evidence id');
        if (ref.alg !== 'sanad-0.1') why.push('alg');
        if (!same(cred.credentialSubject, { id: bundle.subject, skill: bundle.skill, claimedLevel: bundle.claimedLevel })) why.push('credentialSubject differs from the bundle');
        ADD('bundle-hash', why.length === 0, why.length ? why.join('; ') : 'bundle hash ' + h); }
      { const bad = bundle.evidence.filter((e) => e.body.kind !== e.kind || e.body.date !== e.date).map((e) => e.id); ADD('evidence-consistency', bad.length === 0, bad.length ? 'differs in ' + bad.join(', ') : 'kind and date equal the hashed body'); }
      const sittings = bundle.evidence.filter((e) => e.kind === 'sitting');
      if (sittings.length) {
        const why = [];
        for (const e of sittings) {
          const sp = sittingProblems(e.body); if (sp.length) { why.push(e.id + ': ' + sp.join(', ')); continue; }
          const ia = e.body.identityAssurance;
          if (ia) { const st = { type: 'sanad-identity', sittingId: e.body.sittingId, level: ia.level, method: ia.method, checkedBy: ia.checkedBy, date: ia.date, candidateKey: ia.candidateKey };
            const r = await res.verifyStatement({ jws: ia.signature, payload: st, typ: 'sanad-identity+jws', signer: ia.checkedBy, date: ia.date }); if (!r.ok) why.push(e.id + ': identity statement refused (' + r.reason + ')'); }
          if (opts.minIdentityLevel !== undefined) { const need = IDENT.indexOf(opts.minIdentityLevel); if (need < 0) why.push('minIdentityLevel'); else if (IDENT.indexOf(ia?.level) < need) why.push(e.id + ': identity assurance ' + (ia?.level ?? 'absent') + ' is below ' + opts.minIdentityLevel); }
          const absent = ['paperFingerprint', 'strokeLogHead', 'recordingSha256'].filter((k) => !(k in e.body));
          if (absent.length) warnings.push('sitting evidence: ' + e.id + ' carries no ' + absent.join(', '));
        }
        ADD('sitting-evidence', why.length === 0, why.length ? why.join('; ') : sittings.length + ' sitting evidence item(s) well formed');
      }
      { const pre = sanad.assessment + '.'; const bad = [...bundle.evidence.map((e) => e.id), ...bundle.attestations.map((a) => a.id)].filter((id) => !id.startsWith(pre)); ADD('ids', bad.length === 0, bad.length ? 'ids outside the assessment: ' + bad.slice(0, 5).join(', ') : 'ids belong to the assessment'); }
      const sigOk = new Map();
      { const bad = []; for (const a of bundle.attestations) { const { prev, ...st } = core.attestationPayload(a); const r = await res.verifyStatement({ jws: a.signature, payload: st, typ: 'sanad-attestation+jws', signer: a.attestor, date: a.date }); sigOk.set(a.id, r.ok); if (!r.ok) bad.push(a.id + ' (' + r.reason + ')'); }
        ADD('attestor-signatures', bad.length === 0, bad.length ? 'signature refused: ' + bad.join(', ') : bundle.attestations.length + ' attestor signature(s) verify'); }
      // log
      {
        const l = sanad.log, cp = l.checkpoint, why = []; const sigGood = await checkpointOk(cp, res, l.logKey);
        if (!sigGood) why.push('checkpoint signature does not verify with the log key');
        if (sigGood && cp.payload.logId !== l.logId) why.push('checkpoint logId differs');
        if (Array.isArray(opts.trustedLogIds) && !opts.trustedLogIds.includes(l.logId)) why.push('log id is not trusted');
        const leaves = new Set();
        if (sigGood) {
          for (const e of l.entries) {
            let parsed; try { parsed = JSON.parse(e.leaf); if (!exactly(parsed, ['kind', 'ref', 'ts']) || !['commit', 'attestation', 'missing-reveal', 'bundle'].includes(parsed.kind) || !okHex(parsed.ref) || !isoTime(parsed.ts) || core.canonical(parsed) !== e.leaf) throw 0; } catch { why.push('entry ' + e.index + ': invalid leaf'); continue; }
            const pr = l.proofs.find((x) => x.index === e.index);
            if (!pr || pr.size !== cp.payload.size) { why.push('entry ' + e.index + ': no proof for the checkpoint size'); continue; }
            if (!(await verifyInclusion({ leafHash: await leafHash(e.leaf), index: e.index, size: pr.size, proof: pr.proof, root: cp.payload.rootHash }))) { why.push('entry ' + e.index + ': inclusion proof fails'); continue; }
            leaves.add(parsed.kind + ':' + parsed.ref);
          }
          for (const a of bundle.attestations) if (!leaves.has('attestation:' + a.hash)) why.push('attestation ' + a.id + ' is not a verified leaf');
          if (!leaves.has('bundle:' + cred.evidence[0].bundleHash)) why.push('the bundle hash is not a verified leaf');
        }
        ADD('log', why.length === 0, why.length ? why.join('; ') : l.entries.length + ' entries verified against the checkpoint of size ' + cp.payload.size);
      }
      // revocation, witnesses
      if (opts.requireWitnesses !== undefined && opts.requireWitnesses > 0) {
        let wit = []; try { wit = JSON.parse(get('witnesses.json') ?? '[]'); } catch { wit = []; }
        const w = await verifyWitnesses(sanad.log.checkpoint, logKey, res, wit, consistency, opts.trustedWitnesses);
        ADD('witnesses', w.count >= opts.requireWitnesses, w.count >= opts.requireWitnesses ? w.count + ' pinned witness(es) cosigned a consistent checkpoint' : w.count + ' of the required ' + opts.requireWitnesses + ': ' + w.problems.join('; '));
      }
      if (cred.credentialStatus !== undefined) {
        let lists = opts.statusLists; if (lists === undefined && get('status.json') !== undefined) { lists = [JSON.parse(get('status.json'))]; warnings.push('revocation was checked against the snapshot taken at export time; fetch the list again for a current answer'); }
        if (Array.isArray(lists)) { const r = await checkStatus(cred, lists, opts.now ?? Date.now(), res); ADD('revocation', r.ok, r.detail); }
        else if (opts.requireStatus) ADD('revocation', false, 'a status list is required and none was supplied');
        else warnings.push('revocation not checked');
      }
      // pins
      const pin = (name, list, v) => { if (Array.isArray(list)) ADD(name, list.includes(v), list.includes(v) ? 'pinned: ' + v : v + ' is not among the pinned'); else if (opts.allowUnpinned) { ADD(name, true, 'not pinned (allowUnpinned): ' + v); warnings.push(name + ' not pinned'); } else ADD(name, false, v + ' is not pinned'); };
      pin('trusted-issuer', opts.trustedIssuers, cred.issuer); pin('trusted-log-key', opts.trustedLogKeys, logKey);
      if (used.size) { const pk = isObj(opts.pinnedKeys) ? opts.pinnedKeys : {}; const bad = []; for (const [did, ks] of used) for (const k of ks) if (!(Array.isArray(pk[did]) && pk[did].includes(k))) bad.push(did); if (bad.length) warnings.push('embedded DID histories are the issuer\'s own claim; pin the keys: ' + bad.join(', ')); ADD('did-histories', bad.length === 0, bad.length ? 'keys known only from embedded histories and not pinned: ' + bad.join(', ') : 'every did:web key used is pinned'); }
      // process
      { const pr = sanad.process, n = bundle.attestations.length, why = [];
        if (pr.revealed !== n) why.push('revealed differs from the bundle');
        if (pr.committed < pr.revealed || pr.committed > pr.invited) why.push('counts inconsistent');
        if (pr.missing.length !== pr.committed - pr.revealed) why.push('missing');
        if (pr.notCommitted.length !== pr.invited - pr.committed) why.push('notCommitted');
        if (pr.late.some((id) => !pr.missing.includes(id))) why.push('late');
        const have = new Set(bundle.attestations.map((a) => a.id)); if (pr.missing.some((id) => have.has(id))) why.push('missing names an attestation in the bundle');
        ADD('process', why.length === 0, why.length ? why.join('; ') : 'process counts agree with the bundle'); }
      if (Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length) warnings.push('the operator finalized below the template minimum');
      warnings.push('template not supplied: roles and evidence kinds were not checked against it');
      // policy and recognition
      const pol = opts.policy; let recognition = null;
      if (pol === undefined) ADD('policy', false, 'no verifier policy supplied');
      else {
        const pp = core.policyProblems(pol); ADD('policy', pp.length === 0, pp.length ? 'policy refused: ' + pp.join('; ') : 'verifier policy; evaluation day ' + pol.asOf);
        if (pp.length === 0) {
          if ((pol.minAttestorSittings > 0 || pol.minAgreement > 0)) ADD('attestor-statistics', false, 'the policy has a statistics threshold but the only statistics are the issuer\'s');
          try { recognition = core.recognise(bundle, pol, { verifySignature: (a) => sigOk.get(a.id) === true }); } catch (e) { ADD('recognition', false, 'refused: ' + (e && e.message)); }
        }
      }
      return out(recognition && !checks.every((c) => c.ok) ? { ...recognition, unverified: true } : recognition);
    } catch (e) { ADD('internal', false, 'could not be verified: ' + (e && e.message)); return out(); }
  }

  globalThis.SanadVerifier = { verifyTree, readZip, DEFAULT_POLICY };
})(globalThis);
