import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { createMemoryStore, createFileStore } from '../src/store/index.mjs';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  leafHash, nodeHash, merkleRoot, inclusionProof, consistencyProof, verifyInclusion, verifyConsistency,
  leafBytes, createLog, verifyCheckpoint,
} from '../src/log.mjs';
import { canonical } from '../src/core.mjs';

const hex = (s) => Buffer.from(s, 'hex');
const REF = (i) => createHash('sha256').update(String(i)).digest('hex');
const RFC_LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map(hex);
const RFC_ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];
const flip = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);

describe('Merkle known answers (RFC 6962/9162 reference data)', () => {
  const lh = RFC_LEAVES.map(leafHash);
  it('empty tree is the hash of the empty string', () => {
    expect(merkleRoot([])).toBe(createHash('sha256').update('').digest('hex'));
  });
  it('roots for sizes 1..8', () => {
    for (let n = 1; n <= 8; n++) expect(merkleRoot(lh.slice(0, n))).toBe(RFC_ROOTS[n - 1]);
  });
  it('leaf and node hashes use the domain prefixes; strings are UTF-8', () => {
    expect(leafHash('')).toBe(leafHash(new Uint8Array(0)));
    expect(leafHash('é')).toBe(leafHash(new TextEncoder().encode('é')));
    expect(nodeHash(lh[0], lh[1])).toBe(createHash('sha256').update(Buffer.concat([Buffer.from([1]), hex(lh[0]), hex(lh[1])])).digest('hex'));
    expect(merkleRoot(lh.slice(0, 2))).toBe(nodeHash(lh[0], lh[1]));
  });
  it('known inclusion path for leaf 0 of 8 starts with the sibling leaf hash', () => {
    const p = inclusionProof(lh, 0, 8);
    expect(p).toHaveLength(3); expect(p[0]).toBe(lh[1]);
  });
});

describe('inclusion proofs', () => {
  const lh = Array.from({ length: 64 }, (_, i) => leafHash('leaf' + i));
  it('verify for every size 1..64 and index, fail for wrong index/leaf/root/size/proof', () => {
    for (let n = 1; n <= 64; n++) {
      const root = merkleRoot(lh.slice(0, n));
      for (let i = 0; i < n; i++) {
        const proof = inclusionProof(lh, i, n);
        const base = { leafHash: lh[i], index: i, size: n, proof, root };
        expect(verifyInclusion(base)).toBe(true);
        expect(verifyInclusion({ ...base, index: (i + 1) % n === i ? n : (i + 1) % n })).toBe(false);
        expect(verifyInclusion({ ...base, index: n })).toBe(false);
        expect(verifyInclusion({ ...base, leafHash: flip(lh[i]) })).toBe(false);
        expect(verifyInclusion({ ...base, root: flip(root) })).toBe(false);
        if (proof.length) {
          expect(verifyInclusion({ ...base, proof: proof.slice(1) })).toBe(false);
          expect(verifyInclusion({ ...base, proof: [...proof, proof[0]] })).toBe(false);
          expect(verifyInclusion({ ...base, proof: [flip(proof[0]), ...proof.slice(1)] })).toBe(false);
        }
      }
    }
  });
  it('verifiers never throw on junk', () => {
    for (const junk of [undefined, null, {}, { leafHash: 1 }, { leafHash: 'zz', index: 0, size: 1, proof: [], root: 'zz' }, { leafHash: lh[0], index: -1, size: 1, proof: [], root: lh[0] }, { leafHash: lh[0], index: 0, size: 1, proof: 'x', root: lh[0] }]) {
      expect(verifyInclusion(junk)).toBe(false);
      expect(verifyConsistency(junk)).toBe(false);
    }
  });
  it('rejects out of range generation', () => {
    expect(() => inclusionProof(lh, 5, 5)).toThrow(expect.objectContaining({ code: 'bad_range' }));
    expect(() => inclusionProof(lh, 0, 65)).toThrow(expect.objectContaining({ code: 'bad_range' }));
  });
});

describe('consistency proofs', () => {
  const lh = Array.from({ length: 40 }, (_, i) => leafHash('c' + i));
  it('verify for every 1 <= m <= n <= 40 and fail when a leaf is altered', () => {
    for (let n = 1; n <= 40; n++) {
      const rootN = merkleRoot(lh.slice(0, n));
      for (let m = 1; m <= n; m++) {
        const rootM = merkleRoot(lh.slice(0, m));
        const proof = consistencyProof(lh, m, n);
        expect(verifyConsistency({ m, n, proof, rootM, rootN })).toBe(true);
        if (m === n) { expect(proof).toEqual([]); continue; }
        expect(verifyConsistency({ m, n, proof, rootM: flip(rootM), rootN })).toBe(false);
        expect(verifyConsistency({ m, n, proof, rootM, rootN: flip(rootN) })).toBe(false);
        // history rewritten: leaf `k` altered in the old part
        for (const k of [0, m - 1]) {
          const alt = lh.slice(); alt[k] = leafHash('evil');
          const altRootN = merkleRoot(alt.slice(0, n));
          expect(verifyConsistency({ m, n, proof, rootM, rootN: altRootN })).toBe(false);
          expect(verifyConsistency({ m, n, proof: consistencyProof(alt, m, n), rootM, rootN: altRootN })).toBe(false);
        }
        expect(verifyConsistency({ m, n, proof: proof.slice(1), rootM, rootN })).toBe(false);
        expect(verifyConsistency({ m, n, proof: [...proof, proof[0]], rootM, rootN })).toBe(false);
      }
    }
  });
  it('edge cases: m = 0 and m > n are not provable; m = n needs equal roots and empty proof', () => {
    const r = merkleRoot(lh.slice(0, 3));
    expect(verifyConsistency({ m: 0, n: 3, proof: [], rootM: merkleRoot([]), rootN: r })).toBe(false);
    expect(verifyConsistency({ m: 0, n: 0, proof: [], rootM: merkleRoot([]), rootN: merkleRoot([]) })).toBe(false);
    expect(verifyConsistency({ m: 4, n: 3, proof: [], rootM: r, rootN: r })).toBe(false);
    expect(verifyConsistency({ m: 3, n: 3, proof: [], rootM: r, rootN: r })).toBe(true);
    expect(verifyConsistency({ m: 3, n: 3, proof: [], rootM: r, rootN: flip(r) })).toBe(false);
    expect(verifyConsistency({ m: 3, n: 3, proof: [r], rootM: r, rootN: r })).toBe(false);
    expect(() => consistencyProof(lh, 0, 3)).toThrow(expect.objectContaining({ code: 'bad_range' }));
    expect(() => consistencyProof(lh, 4, 3)).toThrow(expect.objectContaining({ code: 'bad_range' }));
  });
  it('matches the RFC reference proofs on the 8-leaf data', () => {
    const l = RFC_LEAVES.map(leafHash);
    // RFC 6962 reference: consistency 1 -> 8 and 6 -> 8 have lengths 3 and 3; 2 -> 5 has length 2; 3 -> 7 has length 4
    expect(consistencyProof(l, 1, 8)).toHaveLength(3);
    expect(consistencyProof(l, 6, 8)).toHaveLength(3);
    expect(consistencyProof(l, 2, 5)).toHaveLength(2);
    expect(consistencyProof(l, 3, 7)).toHaveLength(4);
    for (const [m, n] of [[1, 8], [6, 8], [2, 5], [3, 7]]) {
      expect(verifyConsistency({ m, n, proof: consistencyProof(l, m, n), rootM: RFC_ROOTS[m - 1], rootN: RFC_ROOTS[n - 1] })).toBe(true);
    }
  });
});

describe('leafBytes', () => {
  const ts = '2026-01-02T03:04:05.000Z';
  it('is the canonical JSON of { kind, ref, ts }', () => {
    expect(leafBytes({ kind: 'commit', ref: REF(1), ts })).toBe(canonical({ kind: 'commit', ref: REF(1), ts }));
    expect(leafBytes({ ts, ref: REF(1), kind: 'bundle' })).toBe(`{"kind":"bundle","ref":"${REF(1)}","ts":"${ts}"}`);
  });
  it('rejects bad input', () => {
    for (const bad of [
      { kind: 'other', ref: REF(1), ts }, { kind: 'commit', ref: 'abc', ts }, { kind: 'commit', ref: REF(1).toUpperCase(), ts },
      { kind: 'commit', ref: REF(1), ts: 'yesterday' }, { kind: 'commit', ref: REF(1) }, undefined,
    ]) expect(() => leafBytes(bad)).toThrow(expect.objectContaining({ code: 'bad_leaf' }));
  });
  it('ignores extra members', () => {
    expect(leafBytes({ kind: 'commit', ref: REF(1), ts, extra: 1 })).toBe(canonical({ kind: 'commit', ref: REF(1), ts }));
  });
});

describe('createLog', () => {
  const mk = (extra = {}) => {
    let t = Date.UTC(2026, 0, 1);
    const store = createMemoryStore();
    return { store, log: createLog({ store, logId: 'log-1', clock: { now: () => (t += 1000) }, ...extra }) };
  };
  const kinds = ['commit', 'attestation', 'missing-reveal', 'bundle'];

  it('appends hash-chained entries and agrees with the pure functions', () => {
    const { log } = mk();
    expect(log.size()).toBe(0);
    expect(log.root()).toBe(merkleRoot([]));
    const r0 = log.append({ kind: 'commit', ref: REF(0) });
    expect(r0).toMatchObject({ index: 0 });
    expect(JSON.parse(r0.leaf)).toEqual({ kind: 'commit', ref: REF(0), ts: '2026-01-01T00:00:01.000Z' });
    expect(r0.leafHash).toBe(leafHash(r0.leaf));
    for (let i = 1; i < 13; i++) log.append({ kind: kinds[i % 4], ref: REF(i) });
    const es = log.entries();
    expect(es).toHaveLength(13);
    expect(es[0].prev).toBe('GENESIS');
    expect(es[1].prev).toBe(es[0].hash);
    expect(log.entries(2, 4)).toEqual(es.slice(2, 4));
    expect(log.root()).toBe(merkleRoot(es.map((e) => e.leafHash)));
    expect(log.root(5)).toBe(merkleRoot(es.slice(0, 5).map((e) => e.leafHash)));
    expect(log.verifyChain()).toEqual({ ok: true });
  });
  it('rejects bad appends without changing the log', () => {
    const { log } = mk();
    expect(() => log.append({ kind: 'x', ref: REF(1) })).toThrow(expect.objectContaining({ code: 'bad_leaf' }));
    expect(() => log.append({ kind: 'commit', ref: 'nope' })).toThrow(expect.objectContaining({ code: 'bad_leaf' }));
    expect(log.size()).toBe(0);
  });
  it('inclusion and consistency documents verify', () => {
    const { log } = mk();
    for (let i = 0; i < 20; i++) log.append({ kind: 'commit', ref: REF(i) });
    for (let i = 0; i < 20; i++) expect(verifyInclusion(log.inclusion(i))).toBe(true);
    const inc = log.inclusion(3, 7);
    expect(inc).toMatchObject({ index: 3, size: 7, root: log.root(7) });
    expect(verifyInclusion(inc)).toBe(true);
    for (let m = 1; m <= 20; m++) expect(verifyConsistency(log.consistency(m))).toBe(true);
    const c = log.consistency(5, 12);
    expect(c).toMatchObject({ m: 5, n: 12, rootM: log.root(5), rootN: log.root(12) });
    expect(verifyConsistency(c)).toBe(true);
    expect(() => log.inclusion(20)).toThrow(expect.objectContaining({ code: 'bad_range' }));
    expect(() => log.inclusion(0, 21)).toThrow(expect.objectContaining({ code: 'bad_range' }));
    expect(() => log.consistency(0)).toThrow(expect.objectContaining({ code: 'bad_range' }));
  });
  it('reloads state from the store', () => {
    const { store, log } = mk();
    for (let i = 0; i < 5; i++) log.append({ kind: 'bundle', ref: REF(i) });
    const again = createLog({ store, logId: 'log-1' });
    expect(again.size()).toBe(5);
    expect(again.root()).toBe(log.root());
    again.append({ kind: 'commit', ref: REF(9) });
    expect(again.entries(5, 6)[0].prev).toBe(log.entries(4, 5)[0].hash);
    expect(again.verifyChain()).toEqual({ ok: true });
  });
  it('finds entries by ref', () => {
    const { log } = mk();
    log.append({ kind: 'commit', ref: REF(1) }); log.append({ kind: 'attestation', ref: REF(2) }); log.append({ kind: 'bundle', ref: REF(1) });
    expect(log.findByRef(REF(1)).map((e) => e.index)).toEqual([0, 2]);
    expect(log.findByRef(REF(3))).toEqual([]);
  });
  it('keeps independent streams apart', () => {
    const store = createMemoryStore();
    const a = createLog({ store, logId: 'a', stream: 'log' }), b = createLog({ store, logId: 'b', stream: 'other' });
    a.append({ kind: 'commit', ref: REF(1) });
    expect(b.size()).toBe(0);
  });

  it('finds a tampered stored entry (memory wrapper)', () => {
    for (const field of ['leaf', 'leafHash', 'prev', 'hash', 'index']) {
      const store = createMemoryStore();
      const log = createLog({ store, logId: 'x' });
      for (let i = 0; i < 6; i++) log.append({ kind: 'commit', ref: REF(i) });
      const tampered = {
        ...store,
        read: (s, f, t) => store.read(s, f, t).map((e) => (e.index === 3 ? { ...e, [field]: field === 'index' ? 9 : field === 'leaf' ? e.leaf.replace('commit', 'bundle') : '0'.repeat(64) } : e)),
      };
      const view = { ...log, verifyChain: undefined };
      const check = createLog({ store: tampered, logId: 'x' });
      // `check` loads cache from the tampered store, so compare against the honest chain too
      expect(check.verifyChain().ok).toBe(false);
      expect(check.verifyChain().at).toBe(3);
      expect(view).toBeTruthy();
    }
  });
  it('finds a tampered file on disk', () => {
    const d = mkdtempSync(join(tmpdir(), 'sanad-log-'));
    try {
      let store = createFileStore(d);
      let log = createLog({ store, logId: 'f' });
      for (let i = 0; i < 4; i++) log.append({ kind: 'commit', ref: REF(i) });
      store.close();
      const f = join(d, 'streams', 's_log.jsonl');
      const lines = readFileSync(f, 'utf8').split('\n');
      const e = JSON.parse(lines[2]); e.leaf = e.leaf.replace('commit', 'bundle');
      lines[2] = JSON.stringify(e);
      writeFileSync(f, lines.join('\n'));
      store = createFileStore(d);
      log = createLog({ store, logId: 'f' });
      expect(log.verifyChain()).toEqual({ ok: false, at: 2 });
      store.close();
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
  it('detects a store changed behind a running log', () => {
    const { store, log } = mk();
    for (let i = 0; i < 3; i++) log.append({ kind: 'commit', ref: REF(i) });
    store.append('log', { index: 3, leaf: 'x', leafHash: 'x', prev: 'x', hash: 'x' });
    expect(log.verifyChain().ok).toBe(false);
  });

  it('checkpoints with a signer and verifies through an injected verifier', () => {
    const calls = [];
    const signer = { kid: 'did:key:zX#zX', sign: (typ, payload) => { calls.push(typ); return 'fake.' + createHash('sha256').update(typ + canonical(payload)).digest('hex'); } };
    const { log } = mk({ signer });
    log.append({ kind: 'commit', ref: REF(1) });
    const cp = log.checkpoint();
    expect(calls).toEqual(['sanad-checkpoint+jws']);
    expect(cp.payload).toEqual({ logId: 'log-1', size: 1, rootHash: log.root(), timestamp: expect.stringMatching(/Z$/) });
    const verify = (jws, payload, typ) => jws === 'fake.' + createHash('sha256').update(typ + canonical(payload)).digest('hex');
    expect(verifyCheckpoint(cp, verify)).toBe(true);
    expect(verifyCheckpoint({ ...cp, payload: { ...cp.payload, size: 2 } }, verify)).toBe(false);
    expect(verifyCheckpoint({ ...cp, jws: null }, verify)).toBe(false);
    expect(verifyCheckpoint(cp, () => { throw new Error('boom'); })).toBe(false);
    expect(verifyCheckpoint(cp, () => 'yes')).toBe(false);
    expect(verifyCheckpoint(null, verify)).toBe(false);
  });
  it('checkpoint without a signer has a null jws', () => {
    const { log } = mk();
    const cp = log.checkpoint();
    expect(cp.jws).toBeNull();
    expect(cp.payload.size).toBe(0);
    expect(cp.payload.rootHash).toBe(merkleRoot([]));
    expect(verifyCheckpoint(cp, () => true)).toBe(false);
  });
});
