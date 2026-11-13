import { describe, it, expect } from 'vitest';
import * as H from './helpers.mjs';
import { prepareCommit, prepareReveal, newAttestor, canonical, sha256Hex } from '../static/sanad-client.js';
import { core } from '../src/index.mjs';

// The page's attestor helper (WebCrypto) against the real engine: the key is made by the client and stays there.
describe('static/sanad-client.js (the browser attestor)', () => {
  it('canonical JSON and SHA-256 agree with the core', async () => {
    const v = { b: [1, 'x', null, true], a: { z: 'é"\n', y: 2 } };
    expect(canonical(v)).toBe(core.canonical(v));
    expect(await sha256Hex(canonical(v))).toBe(core.hashOf(v));
  });
  it('commits and reveals signed in WebCrypto are accepted by the engine, and the credential verifies', async () => {
    const { engine, clock } = H.setup();
    H.newAssessment(engine);
    const a = await newAttestor(), b = await newAttestor();
    const i1 = engine.invite('as-1', { attestor: a.did, role: 'examiner', evidence: 'E1' });
    const i2 = engine.invite('as-1', { attestor: b.did, role: 'examiner', evidence: 'E1' });
    const view = () => engine.getAssessment('as-1');
    const ca = await prepareCommit({ attestor: a, assessment: view(), attestationId: i1.attestationId, level: 4 });
    const cb = await prepareCommit({ attestor: b, assessment: view(), attestationId: i2.attestationId, level: 3 });
    engine.commit('as-1', ca.request); engine.commit('as-1', cb.request);
    engine.reveal('as-1', await prepareReveal({ attestor: a, assessment: view(), attestationId: i1.attestationId, secret: ca.secret, date: '2026-03-01' }));
    engine.reveal('as-1', await prepareReveal({ attestor: b, assessment: view(), attestationId: i2.attestationId, secret: cb.secret, date: '2026-03-01' }));
    clock.advance(1000);
    const doc = engine.finalize('as-1');
    const r = engine.verifyCredential(doc, { useRecommendedPolicy: true });
    expect(r.ok).toBe(true); expect(r.recognition.level).toBe(3);
  });
  it('refuses an invitation that belongs to someone else', async () => {
    const { engine, people } = H.setup();
    H.newAssessment(engine);
    const i = engine.invite('as-1', { attestor: people.A.did, role: 'examiner', evidence: 'E1' });
    await expect(prepareCommit({ attestor: await newAttestor(), assessment: engine.getAssessment('as-1'), attestationId: i.attestationId, level: 1 })).rejects.toThrow(/invitation is for/);
  });
});
