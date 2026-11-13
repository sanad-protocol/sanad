import { describe, it, expect } from 'vitest';
import { attestorStats } from '../src/stats.mjs';

const ev = [{ id: 'E1', kind: 'sitting' }, { id: 'E2', kind: 'artifact' }];
const m = (attestor, evidence, level) => ({ attestor, evidence, level });

describe('attestorStats', () => {
  it('empty input', () => { expect(attestorStats([])).toEqual({}); });
  it('worked example: three attestors on one sitting', () => {
    const r = attestorStats([{ evidence: ev, marks: [m('A', 'E1', 3), m('B', 'E1', 4), m('C', 'E1', 1)] }]);
    // A: others [4,1] lower median 1, |3-1|=2 no. B: others [3,1] lower median 1, |4-1|=3 no. C: others [3,4] lower median 3, |1-3|=2 no.
    expect(r).toEqual({ A: { sittings: 1, agreement: 0 }, B: { sittings: 1, agreement: 0 }, C: { sittings: 1, agreement: 0 } });
  });
  it('even number of others uses the lower median', () => {
    const r = attestorStats([{ evidence: ev, marks: [m('A', 'E1', 2), m('B', 'E1', 1), m('C', 'E1', 5), m('D', 'E1', 3)] }]);
    // A: others [1,5,3] sorted [1,3,5] median 3 (odd count), |2-3|=1 yes.
    // B: others [2,5,3] -> [2,3,5] median 3, |1-3|=2 no.
    // C: others [2,1,3] -> [1,2,3] median 2, |5-2|=3 no.
    // D: others [2,1,5] -> [1,2,5] median 2, |3-2|=1 yes.
    expect(r.A.agreement).toBe(1); expect(r.B.agreement).toBe(0); expect(r.C.agreement).toBe(0); expect(r.D.agreement).toBe(1);
    const two = attestorStats([{ evidence: ev, marks: [m('A', 'E1', 2), m('B', 'E1', 0), m('C', 'E1', 4)] }]);
    // A: others [0,4], lower median 0, |2-0|=2 no (an upper median 4 would also give 2)
    expect(two.A.agreement).toBe(0);
    const lower = attestorStats([{ evidence: ev, marks: [m('A', 'E1', 1), m('B', 'E1', 1), m('C', 'E1', 5)] }]);
    // A: others [1,5], lower median 1, |1-1|=0 yes (upper median 5 would be no)
    expect(lower.A.agreement).toBe(1);
  });
  it('an attestor with no co-marks has agreement 0 and still counts sittings', () => {
    expect(attestorStats([{ evidence: ev, marks: [m('A', 'E1', 3)] }])).toEqual({ A: { sittings: 1, agreement: 0 } });
  });
  it('sittings count records with a mark on sitting evidence only, once per record', () => {
    const rec1 = { evidence: ev, marks: [m('A', 'E1', 3), m('B', 'E1', 3), m('A', 'E2', 3)] };
    const rec2 = { evidence: ev, marks: [m('A', 'E2', 3), m('B', 'E2', 3)] };
    const rec3 = { evidence: ev, marks: [m('A', 'E1', 2), m('B', 'E1', 3)] };
    const r = attestorStats([rec1, rec2, rec3]);
    expect(r.A.sittings).toBe(2); expect(r.B.sittings).toBe(2);
  });
  it('agreement aggregates across records and rounds to three decimals', () => {
    const agree = { evidence: ev, marks: [m('A', 'E1', 3), m('B', 'E1', 4)] };
    const differ = { evidence: ev, marks: [m('A', 'E1', 0), m('B', 'E1', 4)] };
    const r = attestorStats([agree, differ, differ]);
    expect(r.A.agreement).toBe(0.333); expect(r.B.agreement).toBe(0.333);
    expect(attestorStats([agree, agree, differ]).A.agreement).toBe(0.667);
  });
  it('items with a single mark are excluded from the denominator', () => {
    const r = attestorStats([{ evidence: ev, marks: [m('A', 'E1', 3), m('B', 'E1', 3), m('A', 'E2', 0)] }]);
    expect(r.A.agreement).toBe(1);
  });
  it('is deterministic and sorts keys', () => {
    const recs = [{ evidence: ev, marks: [m('did:z', 'E1', 3), m('did:a', 'E1', 3), m('did:m', 'E1', 2)] }];
    const a = attestorStats(recs), b = attestorStats(JSON.parse(JSON.stringify(recs)));
    expect(Object.keys(a)).toEqual(['did:a', 'did:m', 'did:z']);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('review fixes', () => {
  it('a key named __proto__ stays an own data member', () => {
    const out = attestorStats([{ evidence: ev, marks: [m('__proto__', 'E1', 3), m('did:a', 'E1', 3)] }]);
    expect(Object.keys(out)).toEqual(['__proto__', 'did:a']);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(out, '__proto__').value).toEqual({ sittings: 1, agreement: 1 });
  });
});
