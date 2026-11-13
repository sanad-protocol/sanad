// Shared fixtures for the engine tests.
import { createEngine } from '../src/engine.mjs';
import { createMemoryStore } from '../src/store/index.mjs';
import { makeSigner, keyPairFromSeed } from '../src/keys.mjs';
import { prepareCommit, prepareReveal } from '../src/attestor.mjs';
import { createDemoAttestor } from '../src/demo-keys.mjs';

export const seedOf = (n) => new Uint8Array(32).fill(n);
export const hexOf = (n) => Buffer.from(seedOf(n)).toString('hex');
export const makeClock = (iso = '2026-03-01T09:00:00.000Z') => { let t = Date.parse(iso); return { now: () => t, advance: (ms) => { t += ms; }, set: (i) => { t = Date.parse(i); } }; };
export const HOUR = 3600000, DAY = 24 * HOUR;

export const template = (over = {}) => ({
  id: 'maths-oral-v1', version: 1, title: 'Maths oral', skill: { id: 'analysis.limits', title: 'Limits' },
  levels: [0, 1, 2, 3, 4, 5].map((level) => ({ level, label: 'L' + level })),
  evidence: [{ key: 'E1', kind: 'sitting', summary: 'Oral sitting' }],
  attestors: { min: 2, max: 3, roles: ['examiner'] }, liveSitting: true, deadlines: { commitHours: 24, revealHours: 48 },
  policy: { id: 'p1', minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8 },
  ...over,
});

export function setup({ store = createMemoryStore(), clock = makeClock(), tpl = template() } = {}) {
  const issuer = makeSigner(keyPairFromSeed(seedOf(1)).privateKey);
  const logSigner = makeSigner(keyPairFromSeed(seedOf(2)).privateKey);
  const engine = createEngine({ store, issuer, logSigner, clock });
  engine.registerTemplate(tpl);
  const people = {};
  for (const [i, n] of ['A', 'B', 'C', 'D'].entries()) people[n] = createDemoAttestor(n, seedOf(10 + i));
  return { engine, store, clock, issuer, logSigner, people, tpl };
}

export const newAssessment = (engine, over = {}) => engine.createAssessment({
  id: 'as-1', templateId: 'maths-oral-v1', subject: 'urn:uuid:11111111-1111-4111-8111-111111111111', claimedLevel: 4,
  evidence: [{ key: 'E1', date: '2026-03-01', summary: 'Oral sitting of 40 minutes', body: { minutes: 40 } }], ...over,
});

export const commitAs = (engine, p, id, attId, level, nonce) => {
  const { request, secret } = prepareCommit({ signer: p.signer, assessment: engine.getAssessment(id), attestationId: attId, level, nonce });
  return { result: engine.commit(id, request), secret };
};
export const revealAs = (engine, p, id, secret, date = '2026-03-01', conflictDeclared = false) =>
  engine.reveal(id, prepareReveal({ signer: p.signer, assessment: engine.getAssessment(id), attestationId: secret.attestationId, secret, date, conflictDeclared }));

export const code = (fn, c) => { try { fn(); } catch (e) { if (e.code !== c) throw new Error(`expected ${c}, got ${e.code}: ${e.message}`); return e; } throw new Error('expected error ' + c); };
