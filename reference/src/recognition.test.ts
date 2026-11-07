import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import vectors from '../vectors.json';
import { canonical, hashOf } from './canon';
import { sha256Hex, sha256HexWebCrypto } from './sha256';
import { sealCredential, type AttestationDraft, type EvidenceDraft } from './seal';
import { applyTamper, type TamperOp } from './tamper';
import { checkIntegrity, recognise } from './recognise';
import { graphFromEdges, infer, type SkillGraph } from './infer';
import { SAMPLE_TAMPER, sampleCredential } from './sample';
import { DEFAULT_POLICY, SANAD_VERSION, type Credential, type Policy } from './types';

type V = { id: string; name: string; policy: Policy; credential: { skill: string; claimedLevel: 0 | 1 | 2 | 3 | 4 | 5; subject: string; evidence: EvidenceDraft[]; attestations: AttestationDraft[]; attestors: Credential['attestors'] }; tamper?: TamperOp[];
  expect: { status: string; level: number; attestedLevel: number | null; confidence: number; dropped: [string, string][]; rules: string[] } };
const build = (v: V): Credential => { const c = sealCredential(v.credential as never); return v.tamper ? applyTamper(c, v.tamper) : c; };

describe('SHA-256 and canonical JSON', () => {
  const samples = ['', 'abc', 'The quick brown fox jumps over the lazy dog', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'b'.repeat(1000), 'ε–δ and الجبر و فارسی 🙂'];
  it('matches node:crypto on edge-sized and unicode inputs', () => { for (const s of samples) expect(sha256Hex(s), JSON.stringify(s.slice(0, 20))).toBe(createHash('sha256').update(s, 'utf8').digest('hex')); });
  it('matches WebCrypto (the second, independent implementation the page uses)', async () => { for (const s of samples) expect(await sha256HexWebCrypto(s)).toBe(sha256Hex(s)); });
  it('has the standard test vector for "abc"', () => { expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'); });
  it('canonical JSON sorts keys, has no whitespace, drops undefined, refuses NaN', () => {
    expect(canonical({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } })).toBe('{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}');
    expect(canonical({ a: undefined, b: null, c: true })).toBe('{"b":null,"c":true}');
    expect(() => canonical({ a: NaN })).toThrow();
    expect(hashOf({ a: 1, b: 2 })).toBe(hashOf({ b: 2, a: 1 }));
  });
});

describe('test vectors (expected values computed by an independent script)', () => {
  for (const v of (vectors as unknown as { vectors: V[] }).vectors) {
    it(`${v.id}: ${v.name}`, () => {
      const r = recognise(build(v), v.policy);
      expect(r.version).toBe(SANAD_VERSION);
      expect(r.status).toBe(v.expect.status);
      expect(r.level).toBe(v.expect.level);
      expect(r.attestedLevel).toBe(v.expect.attestedLevel);
      expect(r.confidence).toBeCloseTo(v.expect.confidence, 3);
      expect(r.dropped.map((d) => [d.id, d.rule]).sort()).toEqual([...v.expect.dropped].sort());
      const seen = new Set(r.explanation.map((s) => s.rule)); for (const rule of v.expect.rules) expect(seen.has(rule as never), `rule ${rule} in the explanation`).toBe(true);
      for (const s of r.explanation) { expect(s.summary.length).toBeGreaterThan(10); expect(s.summary).not.toMatch(/undefined|NaN|\[object/); }
    });
  }
  it('has at least 10 vectors including the cases the protocol must cover', () => {
    const ids = (vectors as unknown as { vectors: V[] }).vectors.map((x) => x.id); expect(ids.length).toBeGreaterThanOrEqual(10);
    for (const must of ['V01', 'V02', 'V03', 'V04', 'V05', 'V06', 'V07', 'V08', 'V09a', 'V09b']) expect(ids).toContain(must);
  });
  it('the same evidence gives different levels under a strict and a loose verifier (V09)', () => {
    const all = (vectors as unknown as { vectors: V[] }).vectors; const a = all.find((x) => x.id === 'V09a')!, b = all.find((x) => x.id === 'V09b')!;
    expect(a.credential).toEqual(b.credential); expect(recognise(build(a), a.policy).level).toBe(4); expect(recognise(build(b), b.policy).level).toBe(3);
  });
});

describe('determinism and explanations', () => {
  const v04 = (vectors as unknown as { vectors: V[] }).vectors.find((x) => x.id === 'V04')!;
  it('input order does not matter and the output is identical byte for byte', () => {
    const c = build(v04); const shuffled: Credential = { ...c, evidence: [...c.evidence].reverse(), attestations: [...c.attestations].reverse() };
    expect(JSON.stringify(recognise(shuffled, v04.policy))).toBe(JSON.stringify(recognise(c, v04.policy)));
  });
  it('does not read the clock: only asOf matters', () => {
    const c = build(v04); const a = recognise(c, { ...v04.policy, asOf: '2026-11-07' }), b = recognise(c, { ...v04.policy, asOf: '2027-11-07' });
    expect(b.confidence).toBeLessThan(a.confidence); expect(recognise(c, v04.policy)).toEqual(a);
  });
  it('explains in plain words which attestor was ignored and why', () => {
    const v06 = (vectors as unknown as { vectors: V[] }).vectors.find((x) => x.id === 'V06')!; const r = recognise(build(v06), v06.policy);
    expect(r.explanation.map((s) => s.summary).join('\n')).toMatch(/Attestor did:sanad:c .* was ignored: a conflict of interest was declared/);
    const v09 = (vectors as unknown as { vectors: V[] }).vectors.find((x) => x.id === 'V09b')!; const r2 = recognise(build(v09), v09.policy);
    expect(r2.explanation.map((s) => s.summary).join('\n')).toMatch(/only 3 sitting\(s\), policy needs 5/);
  });
  it('rejects a policy that cannot be evaluated', () => {
    const c = build(v04); expect(() => recognise(c, { ...v04.policy, halfLifeMonths: 0 })).toThrow(RangeError); expect(() => recognise(c, { ...v04.policy, asOf: 'yesterday' })).toThrow(RangeError);
  });
});

describe('integrity (R1)', () => {
  const c = sealCredential({ skill: 'B09', claimedLevel: 4, subject: 's', attestors: {}, evidence: [{ id: 'E1', kind: 'sitting', date: '2026-10-01', summary: 'x', body: { n: 1 } }],
    attestations: [{ id: 'a1', attestor: 'did:sanad:a', evidence: 'E1', level: 4, date: '2026-10-02' }, { id: 'a2', attestor: 'did:sanad:b', evidence: 'E1', level: 4, date: '2026-10-02' }, { id: 'a3', attestor: 'did:sanad:c', evidence: 'E1', level: 4, date: '2026-10-02' }] });
  it('a freshly sealed credential passes every check', () => { const i = checkIntegrity(c); expect([...i.evidence, ...i.attestations].every((x) => x.ok)).toBe(true); });
  it('a changed evidence body is caught', () => { const i = checkIntegrity(applyTamper(c, [{ evidence: 'E1', set: { 'body.n': 2 } }])); expect(i.evidence[0].ok).toBe(false); expect(i.attestations.every((x) => !x.ok)).toBe(true); });
  it('a changed mark is caught by the hash and by the commitment (blind marking)', () => { const i = checkIntegrity(applyTamper(c, [{ attestation: 'a2', set: { level: 2 } }])); const a2 = i.attestations.find((x) => x.id === 'a2')!; expect(a2.ok).toBe(false); expect(a2.reason).toMatch(/hash/); expect(a2.reason).toMatch(/commitment/); expect(i.attestations.find((x) => x.id === 'a3')!.ok).toBe(true); });
  it('a re-hashed forgery still breaks the chain at the next link', () => {
    const forged = applyTamper(c, [{ attestation: 'a2', set: { prev: 'GENESIS' } }]); const i = checkIntegrity(forged); expect(i.attestations.find((x) => x.id === 'a2')!.reason).toMatch(/chain break/);
  });
  it('an attestation of unknown evidence is dropped', () => { const i = checkIntegrity(applyTamper(c, [{ attestation: 'a1', set: { evidence: 'E9' } }])); expect(i.attestations[0].reason).toMatch(/not in the credential/); });
  it('an invalid date is caught', () => { const i = checkIntegrity(applyTamper(c, [{ evidence: 'E1', set: { date: '2026-13-40' } }])); expect(i.evidence[0].reason).toMatch(/valid yyyy-mm-dd/); });
});

describe('hidden-skill inference (R8)', () => {
  for (const t of (vectors as unknown as { inference: { id: string; name: string; graph: { ids: string[]; requires: Record<string, string[]> }; skill: string; level: 0 | 1 | 2 | 3 | 4 | 5; confidence: number; policy: { maxInferenceDepth: number; inferenceDecay: number }; direct: string[]; expect: [string, number, number, number, string[]][] }[] }).inference) {
    it(`${t.id}: ${t.name}`, () => {
      const g: SkillGraph = { requires: (id) => t.graph.requires[id] ?? [] };
      const out = infer(g, t.skill, t.level, t.confidence, t.policy, t.direct);
      expect(out.map((o) => [o.skill, o.level, o.confidence, o.distance, o.path])).toEqual(t.expect);
      for (const o of out) expect(o.inferred).toBe(true);
    });
  }
  it('builds a graph from the topic map edges (prerequisite, dependent pairs)', () => {
    const g = graphFromEdges(['a', 'b', 'c'], [0, 1, 1, 2]); expect(g.requires('c')).toEqual(['b']); expect(g.requires('b')).toEqual(['a']); expect(g.requires('a')).toEqual([]);
    expect(infer(g, 'c', 4, 1, { maxInferenceDepth: 2, inferenceDecay: 0.5 }).map((x) => [x.skill, x.level, x.confidence])).toEqual([['b', 3, 0.5], ['a', 2, 0.25]]);
  });
});

describe('the sample credential of the explainer page', () => {
  it('is recognised at 4 under the default policy, and the sample tamper drops Ash\'s mark', () => {
    const c = sampleCredential(); const r = recognise(c, DEFAULT_POLICY); expect(r.status).toBe('recognised'); expect(r.level).toBe(4);
    expect(r.dropped.map((d) => d.id)).toEqual(['att-04']); // Fern has one sitting only
    const t = recognise(applyTamper(c, SAMPLE_TAMPER), DEFAULT_POLICY); expect(t.dropped.some((d) => d.id === 'att-02' && d.rule === 'R1')).toBe(true); expect(t.confidence).toBeLessThan(r.confidence);
    expect(recognise(applyTamper(c, SAMPLE_TAMPER), { ...DEFAULT_POLICY, minAttestors: 3 }).status).toBe('provisional');
  });
});
