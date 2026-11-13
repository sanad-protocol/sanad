import { describe, it, expect } from 'vitest';
import { validateTemplate, assertTemplate, templateHash, policyFromTemplate } from '../src/template.mjs';
import { hashOf } from '../src/core.mjs';

const good = () => ({
  id: 'maths-oral-v1', version: 1, title: 'Oral examination in analysis', description: 'Two examiners, one sitting.',
  skill: { id: 'analysis.limits', title: 'Limits', graphHash: 'a'.repeat(64), xwalk: { esco: 'S1.2' } },
  levels: [0, 1, 2, 3, 4, 5].map((level) => ({ level, label: 'L' + level })),
  levelMap: { '1': 0, '6': 5 },
  rubric: [{ id: 'R1', criterion: 'Defines limits', descriptors: { '0': 'none', '5': 'expert' } }],
  evidence: [{ key: 'E1', kind: 'sitting', summary: 'Oral sitting', live: true, minutes: 45 }, { key: 'E2', kind: 'artifact', summary: 'Notes' }],
  attestors: { min: 2, max: 3, roles: ['examiner'] },
  liveSitting: true, deadlines: { commitHours: 24, revealHours: 48 },
  policy: { id: 'maths-oral-strict-1', minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 3, minAgreement: 0.6, maxInferenceDepth: 2, inferenceDecay: 0.7 },
});
const mut = (fn) => { const t = good(); fn(t); return t; };
const bad = (name, fn, needle) => it('refuses ' + name, () => {
  const r = validateTemplate(mut(fn));
  expect(r.ok).toBe(false);
  expect(r.errors.length).toBeGreaterThan(0);
  if (needle) expect(r.errors.join('|')).toContain(needle);
});

describe('validateTemplate', () => {
  it('accepts a full valid template and a minimal one', () => {
    expect(validateTemplate(good())).toEqual({ ok: true, errors: [] });
    const m = mut((t) => { delete t.description; delete t.levelMap; delete t.rubric; delete t.skill.graphHash; delete t.skill.xwalk; t.evidence = [{ key: 'E1', kind: 'sitting', summary: '' }]; });
    expect(validateTemplate(m).ok).toBe(true);
  });
  it('refuses non-objects', () => { for (const v of [null, 3, 'x', []]) expect(validateTemplate(v).ok).toBe(false); });
  bad('unknown top-level member', (t) => { t.extra = 1; }, 'extra');
  bad('unknown skill member', (t) => { t.skill.x = 1; }, 'skill');
  bad('unknown level member', (t) => { t.levels[0].x = 1; }, 'levels[0]');
  bad('unknown rubric member', (t) => { t.rubric[0].x = 1; }, 'rubric[0]');
  bad('unknown evidence member', (t) => { t.evidence[0].x = 1; }, 'evidence[0]');
  bad('unknown attestors member', (t) => { t.attestors.x = 1; }, 'attestors');
  bad('unknown deadlines member', (t) => { t.deadlines.x = 1; }, 'deadlines');
  bad('unknown policy member', (t) => { t.policy.x = 1; }, 'policy');
  bad('policy.asOf', (t) => { t.policy.asOf = '2026-01-01'; }, 'asOf');
  bad('missing policy id', (t) => { delete t.policy.id; }, 'policy');
  for (const f of ['minAttestors', 'requireLive', 'halfLifeMonths', 'minAttestorSittings', 'minAgreement', 'maxInferenceDepth', 'inferenceDecay']) bad('missing policy.' + f, (t) => { delete t.policy[f]; }, f);
  bad('policy.minAttestors 0', (t) => { t.policy.minAttestors = 0; });
  bad('policy.requireLive string', (t) => { t.policy.requireLive = 'yes'; });
  bad('policy.halfLifeMonths 0', (t) => { t.policy.halfLifeMonths = 0; });
  bad('policy.minAttestorSittings negative', (t) => { t.policy.minAttestorSittings = -1; });
  bad('policy.minAgreement 1.1', (t) => { t.policy.minAgreement = 1.1; });
  bad('policy.minAgreement negative', (t) => { t.policy.minAgreement = -0.1; });
  bad('policy.maxInferenceDepth fraction', (t) => { t.policy.maxInferenceDepth = 1.5; });
  bad('policy.inferenceDecay 2', (t) => { t.policy.inferenceDecay = 2; });
  bad('level 6', (t) => { t.levels[5].level = 6; });
  bad('level -1', (t) => { t.levels[0].level = -1; });
  bad('duplicate level', (t) => { t.levels[1].level = 0; }, 'duplicate');
  bad('empty levels', (t) => { t.levels = []; });
  bad('bad id', (t) => { t.id = 'has space'; });
  bad('id too long', (t) => { t.id = 'a'.repeat(201); });
  bad('bad evidence key', (t) => { t.evidence[0].key = 'E 1'; });
  bad('duplicate evidence key', (t) => { t.evidence[1].key = 'E1'; }, 'duplicate');
  bad('bad evidence kind', (t) => { t.evidence[1].kind = 'video'; }, 'kind');
  bad('live not boolean', (t) => { t.evidence[0].live = 1; });
  bad('minutes not positive', (t) => { t.evidence[0].minutes = 0; });
  bad('liveSitting without sitting evidence', (t) => { t.evidence = [{ key: 'E2', kind: 'artifact', summary: '' }]; }, 'sitting');
  bad('liveSitting not boolean', (t) => { t.liveSitting = 'true'; });
  bad('min above max', (t) => { t.attestors.min = 4; }, 'min');
  bad('min below 1', (t) => { t.attestors.min = 0; });
  bad('empty roles', (t) => { t.attestors.roles = []; });
  bad('duplicate roles', (t) => { t.attestors.roles = ['a', 'a']; });
  bad('commitHours zero', (t) => { t.deadlines.commitHours = 0; });
  bad('revealHours negative', (t) => { t.deadlines.revealHours = -2; });
  bad('revealHours string', (t) => { t.deadlines.revealHours = '48'; });
  bad('levelMap value out of range', (t) => { t.levelMap['6'] = 9; });
  bad('levelMap not object', (t) => { t.levelMap = []; });
  bad('skill.xwalk not object', (t) => { t.skill.xwalk = 'x'; });
  bad('missing deadlines', (t) => { delete t.deadlines; }, 'deadlines');
  bad('missing skill', (t) => { delete t.skill; }, 'skill');
  bad('rubric descriptor key out of range', (t) => { t.rubric[0].descriptors['7'] = 'x'; });
  it('allows liveSitting false without sitting evidence', () => {
    expect(validateTemplate(mut((t) => { t.liveSitting = false; t.evidence = [{ key: 'E1', kind: 'auto', summary: '' }]; })).ok).toBe(true);
  });
});

describe('assertTemplate, hash, policy', () => {
  it('assertTemplate returns good and throws bad_template', () => {
    const t = good(); expect(assertTemplate(t)).toBe(t);
    expect(() => assertTemplate(mut((x) => { x.extra = 1; x.liveSitting = 1; }))).toThrow(expect.objectContaining({ code: 'bad_template', message: expect.stringContaining('; ') }));
  });
  it('templateHash is the core hash and is key-order independent', () => {
    const t = good();
    expect(templateHash(t)).toBe(hashOf(t));
    expect(templateHash(t)).toMatch(/^[0-9a-f]{64}$/);
    const rev = Object.fromEntries(Object.entries(t).reverse());
    expect(templateHash(rev)).toBe(templateHash(t));
    expect(templateHash(mut((x) => { x.title = 'other'; }))).not.toBe(templateHash(t));
  });
  it('policyFromTemplate gives the eight core fields without id', () => {
    const p = policyFromTemplate(good(), '2026-11-07');
    expect(p).toEqual({ minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 3, minAgreement: 0.6, maxInferenceDepth: 2, inferenceDecay: 0.7, asOf: '2026-11-07' });
    expect('id' in p).toBe(false);
  });
});

describe('review fixes', () => {
  it('refuses reserved levelMap keys', () => {
    for (const k of ['__proto__', 'constructor', 'toString']) {
      const t = JSON.parse(JSON.stringify(good()));
      Object.defineProperty(t.levelMap, k, { value: 3, enumerable: true, configurable: true, writable: true });
      expect(validateTemplate(t).ok).toBe(false);
    }
  });
  it('refuses xwalk values that cannot be hashed, and absurd deadlines', () => {
    for (const bad of [{ a: NaN }, { a: Infinity }, { a: undefined }, { a: () => 1 }, { a: 1n }, { a: new Date() }]) {
      expect(validateTemplate(mut((t) => { t.skill.xwalk = bad; })).ok).toBe(false);
    }
    const deep = {}; let c = deep; for (let i = 0; i < 20; i++) { c.n = {}; c = c.n; }
    expect(validateTemplate(mut((t) => { t.skill.xwalk = deep; })).ok).toBe(false);
    const cyc = {}; cyc.self = cyc;
    expect(validateTemplate(mut((t) => { t.skill.xwalk = cyc; })).ok).toBe(false);
    expect(validateTemplate(mut((t) => { t.skill.xwalk = { eqf: 6, list: ['a', null, true] }; })).ok).toBe(true);
    expect(validateTemplate(mut((t) => { t.deadlines.revealHours = 1e300; })).ok).toBe(false);
    expect(validateTemplate(mut((t) => { t.deadlines.commitHours = 87601; })).ok).toBe(false);
    expect(validateTemplate(mut((t) => { t.deadlines.commitHours = 87600; })).ok).toBe(true);
  });
});
