// Transparency log: an RFC 9162 (section 2.1) Merkle tree over hash-chained entries.
// Leaf hash = SHA-256(0x00 || leaf bytes); node hash = SHA-256(0x01 || left || right).
// All hashes are lowercase hex strings. Verifiers never throw; they return false.
import { createHash } from 'node:crypto';
import { EngineError } from './errors.mjs';
import { canonical, sha256Hex } from './core.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const KINDS = ['commit', 'attestation', 'missing-reveal', 'bundle'];
const sha = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest('hex'); };
const hexBytes = (h) => Buffer.from(h, 'hex');
const ZERO = Buffer.from([0]), ONE = Buffer.from([1]);

export function leafHash(bytes) {
  const b = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
  return sha(ZERO, b);
}
export const nodeHash = (l, r) => sha(ONE, hexBytes(l), hexBytes(r));

// Largest power of two strictly less than n (n >= 2).
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

export function merkleRoot(leaves) {
  const n = leaves.length;
  if (n === 0) return sha();
  if (n === 1) return leaves[0];
  const k = split(n);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

function checkTree(leaves, size) {
  if (!Array.isArray(leaves) || !Number.isInteger(size) || size < 0 || size > leaves.length) throw new EngineError('bad_range', 'invalid tree size');
}

/** RFC 9162 2.1.3.1 PATH(index, D[size]). */
export function inclusionProof(leaves, index, size) {
  checkTree(leaves, size);
  if (!Number.isInteger(index) || index < 0 || index >= size) throw new EngineError('bad_range', 'index outside tree');
  const path = (m, d) => {
    if (d.length === 1) return [];
    const k = split(d.length);
    return m < k ? [...path(m, d.slice(0, k)), merkleRoot(d.slice(k))] : [...path(m - k, d.slice(k)), merkleRoot(d.slice(0, k))];
  };
  return path(index, leaves.slice(0, size));
}

/** RFC 9162 2.1.4.1 PROOF(m, D[n]). Requires 1 <= m <= n; for m = n the proof is empty. */
export function consistencyProof(leaves, m, n) {
  checkTree(leaves, n);
  if (!Number.isInteger(m) || m < 1 || m > n) throw new EngineError('bad_range', 'consistency needs 1 <= m <= n');
  const sub = (mm, d, b) => {
    if (mm === d.length) return b ? [] : [merkleRoot(d)];
    const k = split(d.length);
    return mm <= k ? [...sub(mm, d.slice(0, k), b), merkleRoot(d.slice(k))] : [...sub(mm - k, d.slice(k), false), merkleRoot(d.slice(0, k))];
  };
  return sub(m, leaves.slice(0, n), true);
}

const okHex = (h) => typeof h === 'string' && HEX64.test(h);
const okProof = (p) => Array.isArray(p) && p.every(okHex);
const isSize = (x) => Number.isSafeInteger(x) && x >= 0;
const half = (x) => Math.floor(x / 2);

/** RFC 9162 2.1.3.2. */
export function verifyInclusion(arg) {
  try {
    const { leafHash: lh, index, size, proof, root } = arg;
    if (!okHex(lh) || !okHex(root) || !okProof(proof) || !isSize(index) || !isSize(size) || index >= size) return false;
    let fn = index, sn = size - 1, r = lh;
    for (const p of proof) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = nodeHash(p, r);
        if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
      } else r = nodeHash(r, p);
      fn = half(fn); sn = half(sn);
    }
    return sn === 0 && r === root;
  } catch { return false; }
}

/**
 * RFC 9162 2.1.4.2. Edge cases: m = n is valid only with an empty proof and equal roots;
 * m = 0 is never provable (the RFC defines proofs for 0 < m <= n) and returns false; m > n is false.
 */
export function verifyConsistency(arg) {
  try {
    const { m, n, proof, rootM, rootN } = arg;
    if (!isSize(m) || !isSize(n) || !okHex(rootM) || !okHex(rootN) || !okProof(proof) || m < 1 || m > n) return false;
    if (m === n) return proof.length === 0 && rootM === rootN;
    const path = (m & (m - 1)) === 0 ? [rootM, ...proof] : [...proof];
    if (path.length === 0) return false;
    let fn = m - 1, sn = n - 1;
    while (fn % 2 === 1) { fn = half(fn); sn = half(sn); }
    let fr = path[0], sr = path[0];
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        fr = nodeHash(c, fr); sr = nodeHash(c, sr);
        if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = half(fn); sn = half(sn); }
      } else sr = nodeHash(sr, c);
      fn = half(fn); sn = half(sn);
    }
    return sn === 0 && fr === rootM && sr === rootN;
  } catch { return false; }
}

/** Canonical JSON of exactly { kind, ref, ts }. */
export function leafBytes({ kind, ref, ts } = {}) {
  if (!KINDS.includes(kind)) throw new EngineError('bad_leaf', 'unknown leaf kind');
  if (typeof ref !== 'string' || !HEX64.test(ref)) throw new EngineError('bad_leaf', 'ref must be 64 lowercase hex characters');
  if (typeof ts !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/.test(ts) || Number.isNaN(Date.parse(ts))) throw new EngineError('bad_leaf', 'ts must be an ISO date-time');
  return canonical({ kind, ref, ts });
}

const entryHash = (e) => sha256Hex(canonical({ index: e.index, leaf: e.leaf, leafHash: e.leafHash, prev: e.prev }));

export function createLog({ store, stream = 'log', logId, signer = null, clock = { now: () => Date.now() } } = {}) {
  if (!store) throw new EngineError('bad_config', 'a store is required');
  if (typeof logId !== 'string' || !logId) throw new EngineError('bad_config', 'logId is required');
  const stored = store.read(stream);
  const hashes = stored.map((e) => e.leafHash); // cache of leaf hashes
  let lastHash = stored.length ? stored[stored.length - 1].hash : 'GENESIS';
  const size = () => hashes.length;
  const sz = (s) => { const v = s === undefined ? size() : s; if (!Number.isInteger(v) || v < 0 || v > size()) throw new EngineError('bad_range', 'size outside log'); return v; };
  const rootOf = (s) => merkleRoot(hashes.slice(0, sz(s)));

  return {
    logId,
    append({ kind, ref } = {}) {
      const leaf = leafBytes({ kind, ref, ts: new Date(clock.now()).toISOString() });
      const lh = leafHash(leaf);
      const entry = { index: hashes.length, leaf, leafHash: lh, prev: lastHash };
      entry.hash = entryHash(entry);
      const at = store.append(stream, entry);
      if (at !== entry.index) throw new EngineError('log_conflict', 'stream index does not match the log', 500);
      hashes.push(lh); lastHash = entry.hash;
      return { index: entry.index, leaf, leafHash: lh };
    },
    size,
    root: (s) => rootOf(s),
    entries: (from = 0, to = size()) => store.read(stream, from, to),
    inclusion(index, s) {
      const n = sz(s);
      const proof = inclusionProof(hashes, index, n);
      return { index, size: n, leafHash: hashes[index], proof, root: rootOf(n) };
    },
    consistency(m, n) {
      const nn = sz(n);
      return { m, n: nn, proof: consistencyProof(hashes, m, nn), rootM: rootOf(m), rootN: rootOf(nn) };
    },
    checkpoint() {
      const payload = { logId, size: size(), rootHash: rootOf(), timestamp: new Date(clock.now()).toISOString() };
      return { payload, jws: signer ? signer.sign('sanad-checkpoint+jws', payload) : null };
    },
    verifyChain() {
      const all = store.read(stream);
      if (all.length !== hashes.length) return { ok: false, at: Math.min(all.length, hashes.length) };
      let prev = 'GENESIS';
      for (let i = 0; i < all.length; i++) {
        const e = all[i];
        if (!e || e.index !== i || typeof e.leaf !== 'string' || e.prev !== prev || e.leafHash !== leafHash(e.leaf) || e.leafHash !== hashes[i] || e.hash !== entryHash(e)) return { ok: false, at: i };
        prev = e.hash;
      }
      return { ok: true };
    },
    findByRef(ref) {
      return store.read(stream).filter((e) => { try { return JSON.parse(e.leaf).ref === ref; } catch { return false; } });
    },
  };
}

/** verify(jws, payload, typ) is injected by the caller. */
export function verifyCheckpoint(checkpoint, verify) {
  try {
    const p = checkpoint?.payload;
    if (!p || typeof checkpoint.jws !== 'string' || typeof verify !== 'function') return false;
    if (typeof p.logId !== 'string' || !isSize(p.size) || !okHex(p.rootHash) || typeof p.timestamp !== 'string') return false;
    return verify(checkpoint.jws, p, 'sanad-checkpoint+jws') === true;
  } catch { return false; }
}
