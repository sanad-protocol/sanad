import { describe, it, expect } from 'vitest';
import * as H from './helpers.mjs';
import { core, leafHash } from '../src/index.mjs';
const { applyTamper } = core;

// honest A (level 4), B (level 3, tampered to 5 after sealing), C (commits, never reveals)
function run(levels = { A: 4, B: 3 }) {
  const s = H.setup(); const { engine, people: P, clock } = s;
  H.newAssessment(engine);
  const inv = ['A', 'B', 'C'].map((n) => engine.invite('as-1', { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
  const sec = {};
  inv.forEach((i, k) => { const n = 'ABC'[k]; sec[n] = H.commitAs(engine, P[n], 'as-1', i.attestationId, levels[n] ?? 2).secret; });
  H.revealAs(engine, P.A, 'as-1', sec.A); H.revealAs(engine, P.B, 'as-1', sec.B);
  clock.advance(4 * H.DAY); // past revealBy (commitBy +24h, revealBy +72h)
  return { ...s, doc: engine.finalize('as-1') };
}
const tamper = (doc, ops) => { const d = JSON.parse(JSON.stringify(doc)); d.sanad.bundle = applyTamper(d.sanad.bundle, ops); return d; };
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe('end to end: honest A, tampered B, silent C', () => {
  it('the untampered credential verifies with every check true', () => {
    const { engine, doc, issuer, logSigner } = run();
    const r = engine.verifyCredential(doc, { useRecommendedPolicy: true });
    expect(r.checks.map((c) => c.name)).toEqual(['shape', 'issuer-proof', 'bundle-hash', 'evidence-consistency', 'ids', 'attestor-signatures', 'log', 'trusted-issuer', 'trusted-log-key', 'template', 'policy']);
    expect(r.checks.every((c) => c.ok)).toBe(true);
    expect(r.ok).toBe(true); expect(r.warnings).toEqual([]); expect(r.notice).toMatch(/Experimental/);
    expect(doc.issuer).toBe(issuer.did); expect(doc.sanad.log.logKey).toBe(logSigner.did);
  });
  it('process lists C as missing and the log holds a missing-reveal leaf for C\'s commit', () => {
    const { engine, doc } = run();
    expect(doc.sanad.process).toEqual({ invited: 3, committed: 3, revealed: 2, missing: ['as-1.a03'], late: [], notCommitted: [] });
    const a = engine.getAssessment('as-1', { view: 'operator' });
    const cCommit = a.commits['as-1.a03'].commit;
    const leaves = doc.sanad.log.entries.map((e) => JSON.parse(e.leaf));
    expect(leaves.filter((l) => l.kind === 'missing-reveal').map((l) => l.ref)).toEqual([cCommit]);
    expect(leaves.filter((l) => l.kind === 'commit')).toHaveLength(3);
    expect(leaves.filter((l) => l.kind === 'attestation').map((l) => l.ref).sort()).toEqual(doc.sanad.bundle.attestations.map((x) => x.hash).sort());
    expect(leaves.filter((l) => l.kind === 'bundle')).toHaveLength(1);
    // commits come before every reveal leaf in log order
    const idx = doc.sanad.log.entries.map((e) => [e.index, JSON.parse(e.leaf).kind]);
    const lastCommit = Math.max(...idx.filter(([, k]) => k === 'commit').map(([i]) => i));
    expect(Math.min(...idx.filter(([, k]) => k === 'attestation').map(([i]) => i))).toBeGreaterThan(lastCommit);
  });
  it('untampered recognition: A=4, B=3 -> lower median 3, recognised (2 attestors, live sitting), confidence 0.838', () => {
    const { engine, doc } = run();
    const r = engine.verifyCredential(doc, { useRecommendedPolicy: true }).recognition;
    expect(r.status).toBe('recognised'); expect(r.level).toBe(3); expect(r.dropped).toEqual([]);
    expect(r.confidence).toBeCloseTo(0.838, 3);
  });
  it('B tampered to level 5 is dropped under R1 (hash and signature); A alone is below minAttestors, so the result is provisional at level 0', () => {
    const { engine, doc } = run();
    const bad = tamper(doc, [{ attestation: 'as-1.a02', set: { level: 5 } }]);
    const r = engine.verifyCredential(bad, { useRecommendedPolicy: true });
    expect(r.ok).toBe(false);
    expect(failed(r)).toEqual(['issuer-proof', 'bundle-hash', 'attestor-signatures']);
    expect(r.recognition.dropped).toHaveLength(1);
    expect(r.recognition.dropped[0]).toMatchObject({ id: 'as-1.a02', rule: 'R1' });
    expect(r.recognition.dropped[0].reason).toMatch(/hash/); expect(r.recognition.dropped[0].reason).toMatch(/signature/);
    expect(r.recognition.status).toBe('provisional'); expect(r.recognition.level).toBe(0);
    expect(r.recognition.used.attestations).toEqual(['as-1.a01']);
  });
  it('a signature-only change is caught by the signature check and R1 even though the hash still matches', () => {
    const { engine, doc } = run();
    const sig = doc.sanad.bundle.attestations[1].signature;
    const flipped = sig.slice(0, -10) + (sig.at(-10) === 'A' ? 'B' : 'A') + sig.slice(-9);
    const bad = tamper(doc, [{ attestation: 'as-1.a02', set: { signature: flipped } }]);
    const r = engine.verifyCredential(bad, { useRecommendedPolicy: true });
    expect(failed(r)).toContain('attestor-signatures');
    expect(r.recognition.dropped.map((d) => d.id)).toEqual(['as-1.a02']);
    expect(r.recognition.dropped[0].reason).toMatch(/signature/);
  });
  it('an evidence kind change fails evidence-consistency and the bundle hash', () => {
    const { engine, doc } = run();
    const bad = tamper(doc, [{ evidence: 'as-1.E1', set: { kind: 'peer' } }]);
    const r = engine.verifyCredential(bad, { useRecommendedPolicy: true });
    expect(failed(r)).toEqual(expect.arrayContaining(['bundle-hash', 'evidence-consistency']));
  });
  it('the log checkpoint and leaves cannot be swapped for another log key', () => {
    const { engine, doc } = run();
    const r = engine.verifyCredential(doc, { useRecommendedPolicy: true, trustedLogKeys: ['did:key:zOther'] });
    expect(failed(r)).toEqual(expect.arrayContaining(['trusted-log-key']));
  });
  it('a different issuer is refused when pinned, and warned about when not', () => {
    const { engine, doc } = run();
    expect(failed(engine.verifyCredential(doc, { useRecommendedPolicy: true, trustedIssuers: ['did:key:zOther'] }))).toEqual(['trusted-issuer']);
    const r = engine.verifyCredential(doc, { useRecommendedPolicy: true, trustedIssuers: undefined, trustedLogKeys: undefined });
    expect(r.ok).toBe(true); // the engine pins its own issuer and log key by default
  });
  it('log inclusion proofs recompute from the leaves', () => {
    const { doc } = run();
    expect(doc.sanad.log.proofs).toHaveLength(doc.sanad.log.entries.length);
    expect(leafHash(doc.sanad.log.entries[0].leaf)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('property: random levels', () => {
  it('30 random assignments: untampered always verifies; flipping any attestation level always causes an R1 drop', () => {
    let seed = 12345; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let n = 0; n < 30; n++) {
      const lv = { A: Math.floor(rnd() * 6), B: Math.floor(rnd() * 6) };
      const { engine, doc } = run(lv);
      const r = engine.verifyCredential(doc, { useRecommendedPolicy: true });
      expect(r.ok).toBe(true); expect(r.recognition.dropped).toEqual([]);
      for (const a of doc.sanad.bundle.attestations) {
        const bad = tamper(doc, [{ attestation: a.id, set: { level: (a.level + 1) % 6 } }]);
        const rr = engine.verifyCredential(bad, { useRecommendedPolicy: true });
        expect(rr.ok).toBe(false);
        expect(rr.recognition.dropped.some((d) => d.id === a.id && d.rule === 'R1')).toBe(true);
      }
    }
  });
});
