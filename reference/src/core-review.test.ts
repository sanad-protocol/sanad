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
