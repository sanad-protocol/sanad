import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createToyHost, thirdPartyCheck, gradeToLevel, levelToGrade } from '../examples/toy-host.mjs';
import { template, makeClock } from './helpers.mjs';

describe('toy host (the worked example of the integration tutorial), using the vendored bundle', () => {
  const clock = makeClock();
  const mk = () => createToyHost({ template: template(), now: clock.now });
  it('maps host grades 1..6 to levels 0..5 and back', () => {
    expect([1, 2, 3, 4, 5, 6].map(gradeToLevel)).toEqual([0, 1, 2, 3, 4, 5]);
    expect([0, 1, 2, 3, 4, 5].map(levelToGrade)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(() => gradeToLevel(0)).toThrow();
  });
  it('a host sitting yields a credential; a third party verifies it with its own policy; the host keeps consistent checkpoints', () => {
    const host = mk();
    host.enrol('s-17', 'Ada Example');
    const doc = host.sit({ hostId: 's-17', claimedGrade: 5, examiners: [{ grade: 5 }, { grade: 4 }], date: '2026-03-01' });
    host.sit({ hostId: 's-17', claimedGrade: 3, examiners: [{ grade: 3 }, { grade: 3 }], date: '2026-03-01' });
    expect(host.checkpoints).toHaveLength(2);
    const ok = thirdPartyCheck(doc, { issuer: host.pinned.issuer, logKey: host.pinned.logKey });
    expect(ok.ok).toBe(true); expect(ok.recognition.level).toBe(3);
    const strict = thirdPartyCheck(doc, { issuer: host.pinned.issuer, logKey: host.pinned.logKey, policy: { minAttestors: 3, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 } });
    expect(strict.recognition.status).toBe('provisional');
    expect(thirdPartyCheck(doc, { issuer: 'did:key:zSomeoneElse', logKey: host.pinned.logKey }).ok).toBe(false);
    // personal data stays in the host: the credential and the engine's store hold the pseudonym only
    expect(JSON.stringify(doc)).not.toContain('Ada'); expect(JSON.stringify(doc)).not.toContain('s-17');
  });
  it('the example imports the committed bundle, not the sources', () => {
    const src = readFileSync(fileURLToPath(new URL('../examples/toy-host.mjs', import.meta.url)), 'utf8');
    expect(src).toMatch(/from '\.\.\/dist\/sanad-engine\.mjs'/); expect(src).not.toMatch(/from '\.\.\/src\//);
  });
});
