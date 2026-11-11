// Review round: every policy field is validated, one mark per attestor per evidence item, and the verifier's allow-list.
import { describe, expect, it } from 'vitest';
import * as core from './index';
import { DEFAULT_POLICY } from './types';

const S = () => core.sampleCredential();

describe('policy validation (H1)', () => {
  const bad: [string, Record<string, unknown>][] = [
    ['minAttestors string', { minAttestors: 'x' }], ['minAttestors fraction', { minAttestors: 1.5 }], ['minAttestors 0', { minAttestors: 0 }], ['minAttestors NaN', { minAttestors: NaN }],
    ['requireLive string', { requireLive: 'yes' }], ['halfLife 0', { halfLifeMonths: 0 }], ['halfLife Infinity', { halfLifeMonths: Infinity }],
    ['sittings string', { minAttestorSittings: '3' }], ['sittings negative', { minAttestorSittings: -1 }],
    ['agreement string', { minAgreement: '0.9' }], ['agreement above 1', { minAgreement: 1.1 }],
    ['depth fraction', { maxInferenceDepth: 1.5 }], ['depth negative', { maxInferenceDepth: -1 }],
    ['decay above 1', { inferenceDecay: 2 }], ['decay NaN', { inferenceDecay: NaN }], ['asOf wrong', { asOf: '2026-13-40' }],
  ];
  for (const [name, over] of bad) it('refuses ' + name, () => { expect(() => core.recognise(S(), { ...DEFAULT_POLICY, ...over } as never)).toThrow(RangeError); });
  it('refuses a partial policy and a missing policy', () => {
    expect(() => core.recognise(S(), { halfLifeMonths: 24, asOf: '2026-11-07' } as never)).toThrow(/minAttestors/);
    expect(() => core.recognise(S(), undefined as never)).toThrow(RangeError);
    expect(core.policyProblems({})).toHaveLength(8);
    expect(core.policyProblems(DEFAULT_POLICY)).toEqual([]);
  });
  it('infer refuses bad depth and decay', () => {
    const g = { requires: () => [] };
    expect(() => core.infer(g, 's', 3, 0.5, { maxInferenceDepth: -1, inferenceDecay: 0.5 })).toThrow(RangeError);
    expect(() => core.infer(g, 's', 3, 0.5, { maxInferenceDepth: 1, inferenceDecay: 7 })).toThrow(RangeError);
  });
});

describe('duplicate marks (H4)', () => {
  it('a second mark by the same attestor on the same evidence item is dropped under R1', () => {
    const c = S();
    const first = c.attestations[0];
    const dup = core.sealCredential({
      skill: c.skill, claimedLevel: c.claimedLevel, subject: c.subject, attestors: c.attestors,
      evidence: c.evidence.map(({ hash: _h, ...e }) => e),
      attestations: [
        { id: 'z-01', attestor: first.attestor, evidence: first.evidence, level: 5, date: first.date },
        { id: 'z-02', attestor: first.attestor, evidence: first.evidence, level: 5, date: first.date, nonce: 'other-nonce-0123456789' },
      ],
    });
    const r = core.recognise(dup, DEFAULT_POLICY);
    expect(r.dropped).toContainEqual(expect.objectContaining({ id: 'z-02', rule: 'R1' }));
    expect(r.dropped.find((d) => d.id === 'z-02')!.reason).toMatch(/duplicate mark/);
    expect(r.used.attestations).not.toContain('z-02');
  });
});

describe('allow-list (H2)', () => {
  it('attestations by attestors outside the list are ignored under R2 with a reason', () => {
    const c = S();
    const keep = c.attestations[0].attestor;
    const r = core.recognise(c, DEFAULT_POLICY, { allowAttestor: (d) => d === keep });
    expect(r.dropped.some((d) => d.rule === 'R2' && /allow-list/.test(d.reason))).toBe(true);
    expect(r.used.attestations.every((id) => c.attestations.find((a) => a.id === id)!.attestor === keep)).toBe(true);
  });
});

describe('second review: small hardening', () => {
  it('claimedLevel must be an integer from 0 to 5', () => {
    for (const v of [6, -1, 2.5, NaN]) { const c = { ...S(), claimedLevel: v as never }; expect(() => core.recognise(c, DEFAULT_POLICY)).toThrow(/claimedLevel/); }
  });
  it('attestor statistics are read from own properties and must be numbers', () => {
    const c = S(); const who = c.attestations[0].attestor;
    const a = core.recognise({ ...c, attestors: { ...c.attestors, [who]: { sittings: '99' as never, agreement: '1' as never } } }, DEFAULT_POLICY);
    expect(a.dropped.some((d) => d.rule === 'R2' && /only 0 sitting/.test(d.reason))).toBe(true);
    const o = Object.create({ [who]: { sittings: 99, agreement: 1 } }) as typeof c.attestors; // inherited, not own
    expect(core.recognise({ ...c, attestors: o }, DEFAULT_POLICY).dropped.some((d) => d.rule === 'R2')).toBe(true);
  });
  it('the pseudo-attestor "replay" cannot be a human attestor', () => {
    const c = S(); const e = c.evidence.find((x) => x.kind === 'sitting')!;
    const forged = core.sealCredential({ skill: c.skill, claimedLevel: c.claimedLevel, subject: c.subject, attestors: { replay: { sittings: 9, agreement: 1 } }, evidence: c.evidence.map(({ hash: _h, ...x }) => x), attestations: [{ id: 'r-1', attestor: 'replay', evidence: e.id, level: 5, date: e.date }] });
    const r = core.recognise(forged, DEFAULT_POLICY);
    expect(r.dropped).toContainEqual(expect.objectContaining({ id: 'r-1', rule: 'R1' }));
  });
});

describe('pinned behaviour that differs from the specification text (see docs/SPEC-DECISIONS-NEEDED.md)', () => {
  const policy = { ...DEFAULT_POLICY, halfLifeMonths: 12, minAttestors: 1, requireLive: false, minAttestorSittings: 0, minAgreement: 0, asOf: '2026-11-07' };
  const at = (days: number) => { const d = new Date(Date.UTC(2026, 10, 7) - days * 86400000).toISOString().slice(0, 10); return core.sealCredential({ skill: 's', claimedLevel: 3, subject: 'urn:uuid:x', attestors: { 'did:sanad:a': { sittings: 5, agreement: 1 } }, evidence: [{ id: 'e1', kind: 'sitting', date: d, summary: '', body: { kind: 'sitting', date: d } }], attestations: [{ id: 'a1', attestor: 'did:sanad:a', evidence: 'e1', level: 3, date: d }] }); };
  it('month length: 1461 days is exactly 4 half-lives of 12 months at 30.4375 days, so the core keeps the evidence; the specification text value 30.436875 would drop it', () => {
    expect(core.recognise(at(1461), policy).used.evidence).toEqual(['e1']);
    expect(core.recognise(at(1462), policy).dropped).toContainEqual(expect.objectContaining({ id: 'e1', rule: 'R2' }));
    expect(1461 / 30.4375).toBe(48); expect(1461 / 30.436875).toBeGreaterThan(48);
  });
  it('chain rule: the core drops only the attestation whose own prev link fails, not its honest successor (the specification text says both)', () => {
    const c = S(); expect(c.attestations.length).toBeGreaterThan(2);
    const bad = core.applyTamper(c, [{ attestation: c.attestations[1].id, set: { prev: 'f'.repeat(64) } }]);
    const r = core.recognise(bad, DEFAULT_POLICY);
    expect(r.dropped.filter((d) => d.rule === 'R1').map((d) => d.id)).toContain(c.attestations[1].id);
    expect(r.dropped.filter((d) => d.rule === 'R1').map((d) => d.id)).not.toContain(c.attestations[2].id);
  });
  it('byte-level pins: the sealed sample credential has these hashes (the 20 vectors are sealed at run time and pin none)', () => {
    const c = S();
    expect(c.evidence.map((e) => e.hash.slice(0, 16))).toMatchSnapshot();
    expect(c.attestations.map((a) => [a.commit.slice(0, 16), a.hash.slice(0, 16)])).toMatchSnapshot();
  });
});
