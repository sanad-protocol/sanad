// Scripted end-to-end runs of the three example templates. DEMONSTRATION: the script plays every attestor with keys it generates
// (src/demo-keys.mjs); a real deployment never does that, each attestor signs on their own device.
//   node engine/examples/run.mjs [maths-oral|code-portfolio|welding-practical]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEngine, createMemoryStore, makeSigner, keyPairFromSeed, prepareCommit, prepareReveal } from '../src/index.mjs';
import { createDemoAttestor } from '../src/demo-keys.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const seed = (n) => new Uint8Array(32).fill(n);
const HOUR = 3600000;

/** name -> { evidence per template key, marks: [{ role, evidence key, level }], claimedLevel } */
export const SCENARIOS = {
  'maths-oral': {
    claimedLevel: 4,
    evidence: [{ key: 'E1', date: '2026-03-02', summary: 'Oral sitting of 40 minutes', body: { minutes: 40, room: 'online' } }],
    marks: [{ role: 'examiner', evidence: 'E1', level: 4 }, { role: 'examiner', evidence: 'E1', level: 3 }, { role: 'examiner', evidence: 'E1', level: 4 }],
  },
  'code-portfolio': {
    claimedLevel: 3,
    evidence: [
      { key: 'E1', date: '2026-03-02', summary: 'Repository snapshot', body: { commit: '3f2a9c1', treeHash: 'e6b1d0a4' } },
      { key: 'E2', date: '2026-03-03', summary: 'Peer review', body: { words: 410 } },
    ],
    marks: [{ role: 'reviewer', evidence: 'E1', level: 3 }, { role: 'reviewer', evidence: 'E1', level: 3 }, { role: 'reviewer', evidence: 'E2', level: 2 }, { role: 'reviewer', evidence: 'E2', level: 3 }],
  },
  'welding-practical': {
    claimedLevel: 3,
    evidence: [
      { key: 'E1', date: '2026-03-02', summary: 'Live practical', body: { minutes: 60, nativeClaim: 'native-4' } },
      { key: 'E2', date: '2026-03-02', summary: 'Bend test', body: { recordHash: '9d1c5b77', result: 'pass' } },
    ],
    marks: [{ role: 'examiner', evidence: 'E1', level: 3 }, { role: 'examiner', evidence: 'E1', level: 3 }, { role: 'observer', evidence: 'E1', level: 3 }],
  },
};

export function runExample(name, log = () => {}) {
  const sc = SCENARIOS[name];
  if (!sc) throw new Error('unknown example ' + name + ' (try ' + Object.keys(SCENARIOS).join(', ') + ')');
  const template = JSON.parse(readFileSync(join(here, name + '.template.json'), 'utf8'));
  let now = Date.parse('2026-03-02T09:00:00.000Z');
  const clock = { now: () => now };
  const engine = createEngine({
    store: createMemoryStore(), clock,
    issuer: makeSigner(keyPairFromSeed(seed(1)).privateKey), logSigner: makeSigner(keyPairFromSeed(seed(2)).privateKey),
  });
  log('template ' + engine.registerTemplate(template).hash);
  const subject = 'urn:uuid:5b0d2c1e-8a4f-4b7e-9c3d-2f6a1e7b8c90';
  const a = engine.createAssessment({ id: 'as-' + name, templateId: template.id, subject, claimedLevel: sc.claimedLevel, evidence: sc.evidence });
  const people = sc.marks.map((m, i) => ({ ...m, who: createDemoAttestor('P' + i, seed(30 + i)) }));
  const invs = people.map((p) => engine.invite(a.id, { attestor: p.who.did, role: p.role, evidence: p.evidence }));
  log('invited ' + invs.length + ' attestors');
  const secrets = people.map((p, i) => {
    const { request, secret } = prepareCommit({ signer: p.who.signer, assessment: engine.getAssessment(a.id), attestationId: invs[i].attestationId, level: p.level });
    engine.commit(a.id, request);
    return secret;
  });
  log('all commits in; reveals open');
  now += 26 * HOUR;
  people.forEach((p, i) => engine.reveal(a.id, prepareReveal({ signer: p.who.signer, assessment: engine.getAssessment(a.id), attestationId: invs[i].attestationId, secret: secrets[i], date: '2026-03-03' })));
  const credential = engine.finalize(a.id);
  const report = engine.verifyCredential(credential);
  // two verifiers, two policies, one chain
  const strict = engine.verifyCredential(credential, { policy: { minAttestors: 5, requireLive: true, halfLifeMonths: 12, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 } });
  return { engine, template, credential, report, strictReport: strict };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const names = process.argv[2] ? [process.argv[2]] : Object.keys(SCENARIOS);
  for (const n of names) {
    const r = runExample(n, (s) => console.log('  ' + s));
    const rec = r.report.recognition, st = r.strictReport.recognition;
    console.log(`${n}: checks ${r.report.checks.every((c) => c.ok) ? 'all pass' : 'FAILED'}; template policy -> ${rec.status} level ${rec.level} (confidence ${rec.confidence}); a stricter verifier -> ${st.status} level ${st.level}`);
  }
}
