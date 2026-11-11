import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runExample, SCENARIOS } from '../examples/run.mjs';

const script = fileURLToPath(new URL('./crosscheck/xcheck.py', import.meta.url));
const py = spawnSync('python3', ['--version'], { encoding: 'utf8' });
const have = py.status === 0;
const dir = mkdtempSync(join(tmpdir(), 'sanad-xcheck-'));
const run = (doc, asOf = '2026-03-03', extra = []) => { const f = join(dir, 'c.json'); writeFileSync(f, JSON.stringify(doc)); return spawnSync('python3', [script, f, '--as-of', asOf, '--allow-unpinned', ...extra], { encoding: 'utf8' }); };
const runPinned = (doc, pins, asOf = '2026-03-03') => { const f = join(dir, 'p.json'); writeFileSync(f, JSON.stringify(doc)); return spawnSync('python3', [script, f, '--as-of', asOf, ...pins], { encoding: 'utf8' }); };

describe.skipIf(!have)('independent Python verifier (stdlib only)', () => {
  for (const name of Object.keys(SCENARIOS)) {
    it(name + ': every check passes in the second implementation, and its recognition agrees on status and level', () => {
      const r = runExample(name);
      const out = run(r.credential);
      expect(out.stdout.split('\n').filter((l) => l.startsWith('FAIL'))).toEqual([]);
      expect(out.status).toBe(0);
      const m = /python recognition \('([a-z-]+)', (\d), ([\d.]+)\)/.exec(out.stdout);
      expect(m, out.stdout.slice(-300)).not.toBeNull();
      const pol = { minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8, asOf: '2026-03-03' };
      const mine = r.engine.verifyCredential(r.credential, { policy: pol }).recognition;
      expect([m[1], Number(m[2])]).toEqual([mine.status, mine.level]);
    });
  }
  it('a tampered credential fails in the second implementation as well', () => {
    const r = runExample('maths-oral');
    const bad = JSON.parse(JSON.stringify(r.credential)); bad.sanad.bundle.attestations[0].level = 5;
    const out = run(bad);
    expect(out.stdout.split('\n').some((l) => l.startsWith('FAIL'))).toBe(true);
  });
  it('a forged signature is refused by its own Ed25519 code', () => {
    const r = runExample('maths-oral');
    const bad = JSON.parse(JSON.stringify(r.credential));
    const a = bad.sanad.bundle.attestations[1]; a.signature = a.signature.slice(0, -10) + (a.signature.at(-10) === 'A' ? 'B' : 'A') + a.signature.slice(-9);
    const out = run(bad);
    expect(out.stdout).toMatch(/FAIL attestor JWS/);
  });
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
});

const rb = spawnSync('ruby', ['--version'], { encoding: 'utf8' });
const rubyScript = fileURLToPath(new URL('./crosscheck/sanad_verify.rb', import.meta.url));
const runRb = (doc, asOf = '2026-03-03', extra = ['--allow-unpinned']) => { const f = join(dir, 'r.json'); writeFileSync(f, JSON.stringify(doc)); return spawnSync('ruby', [rubyScript, f, asOf, '36', ...extra], { encoding: 'utf8' }); };

describe.skipIf(rb.status !== 0)('independent Ruby verifier (standard library only)', () => {
  it('its own Ed25519 and canonical JSON agree with the RFC 8032 vector and ECMAScript number formatting', () => {
    const out = spawnSync('ruby', [rubyScript, '--selftest'], { encoding: 'utf8' }).stdout;
    expect(out).toMatch(/RFC8032 vector1: \[true/); expect(out).toMatch(/"a":\[1e\+21,1e-7,100,0\.000001,123456789012345680000,0,/);
  });
  for (const name of Object.keys(SCENARIOS)) {
    it(name + ': every check passes in the Ruby implementation and its status and level agree', () => {
      const r = runExample(name);
      const out = runRb(r.credential);
      expect(out.stdout.split('\n').filter((l) => l.startsWith('FAIL'))).toEqual([]);
      expect(out.stdout).toMatch(/OVERALL: PASS/);
      const m = /RECOGNITION: status=([a-z-]+) level=(\d)/.exec(out.stdout);
      const pol = { minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.7, asOf: '2026-03-03' };
      const mine = r.engine.verifyCredential(r.credential, { policy: pol }).recognition;
      expect([m[1], Number(m[2])]).toEqual([mine.status, mine.level]);
    });
  }
  it('a tampered credential fails in Ruby too', () => {
    const r = runExample('maths-oral'); const bad = JSON.parse(JSON.stringify(r.credential)); bad.sanad.bundle.attestations[0].level = 5;
    expect(runRb(bad).stdout).toMatch(/OVERALL: FAIL/);
  });
});



// ---- rehearsal findings (E1 to E3): shared log, positional as-of, pinning, clean failure
import { createEngine, createMemoryStore, makeSigner, keyPairFromSeed, prepareCommit, prepareReveal } from '../src/index.mjs';
import { createDemoAttestor } from '../src/demo-keys.mjs';
const sd = (n) => new Uint8Array(32).fill(n);
function twoOnOneLog({ issuerSeed = 1, logSeed = 2 } = {}) {
  const engine = createEngine({ store: createMemoryStore(), issuer: makeSigner(keyPairFromSeed(sd(issuerSeed)).privateKey), logSigner: makeSigner(keyPairFromSeed(sd(logSeed)).privateKey), logId: 'shared-log', clock: { now: () => Date.parse('2026-03-02T10:00:00Z') } });
  engine.registerTemplate({ id: 't', version: 1, title: 't', skill: { id: 's', title: 's' }, levels: [0, 1, 2, 3, 4, 5].map((l) => ({ level: l, label: 'L' + l })), evidence: [{ key: 'E1', kind: 'sitting', summary: 's' }], attestors: { min: 2, max: 3, roles: ['examiner'] }, liveSitting: true, deadlines: { commitHours: 24, revealHours: 48 }, policy: { id: 'p', minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.7 } });
  const people = [createDemoAttestor('A', sd(10)), createDemoAttestor('B', sd(11))];
  const run = (id) => {
    engine.createAssessment({ id, templateId: 't', subject: 'urn:uuid:22222222-2222-4222-8222-222222222222', claimedLevel: 3, evidence: [{ key: 'E1', date: '2026-03-02', summary: 's', body: {} }] });
    const inv = people.map((p) => engine.invite(id, { attestor: p.did, role: 'examiner', evidence: 'E1' }));
    const sec = people.map((p, i) => { const { request, secret } = prepareCommit({ signer: p.signer, ticket: engine.ticketFor(id, inv[i].attestationId), level: 3 }); engine.commit(id, request); return secret; });
    people.forEach((p, i) => engine.reveal(id, prepareReveal({ signer: p.signer, ticket: engine.ticketFor(id, inv[i].attestationId), secret: sec[i], date: '2026-03-02' })));
    return engine.finalize(id);
  };
  const first = run('a-1'), second = run('a-2');
  return { engine, first, second };
}

describe('E1: a correct credential that is not first on its log verifies in every implementation', () => {
  const { first, second } = twoOnOneLog();
  it('the embedded entries are a subset of the log (the second credential has a checkpoint larger than its entries)', () => {
    expect(second.sanad.log.checkpoint.payload.size).toBeGreaterThan(second.sanad.log.entries.length);
    expect(second.sanad.log.entries[0].index).toBeGreaterThan(0);
  });
  it.skipIf(!have)('Python: both credentials pass', () => { for (const c of [first, second]) { const o = run(c); expect(o.stdout.split('\n').filter((l) => l.startsWith('FAIL'))).toEqual([]); expect(o.status).toBe(0); } });
  it.skipIf(rb.status !== 0)('Ruby: both credentials pass', () => { for (const c of [first, second]) { const o = runRb(c); expect(o.stdout.split('\n').filter((l) => l.startsWith('FAIL')), o.stdout).toEqual([]); expect(o.stdout).toMatch(/OVERALL: PASS/); } });
});

describe.skipIf(rb.status !== 0)('E2: the Ruby evaluation day is honoured, and explains the confidence gap', () => {
  it('the positional as-of argument and --as-of change the result; with the same day the confidence equals the engine\'s (the earlier 0.933 against 0.936 came from the defaults of the verifier, evaluation day 2026-03-12 and half-life 24 months, being used because the positional arguments were ignored)', () => {
    const r = runExample('maths-oral');
    const pol = (asOf) => ({ minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.7, asOf });
    const conf = (out) => Number(/confidence=([\d.]+)/.exec(out.stdout)[1]);
    for (const day of ['2026-03-03', '2026-03-12', '2027-01-15']) {
      const mine = r.engine.verifyCredential(r.credential, { policy: pol(day) }).recognition.confidence;
      expect(Math.abs(conf(runRb(r.credential, day)) - mine), day).toBeLessThanOrEqual(0.0005);
      expect(Math.abs(conf(runRb(r.credential, '2020-01-01', ['--as-of', day, '--allow-unpinned'])) - mine), 'flag ' + day).toBeLessThanOrEqual(0.0005);
    }
    expect(conf(runRb(r.credential, '2026-03-03'))).toBe(0.936);
    // the old gap: with no day and no half-life given, the verifier's defaults (2026-03-12, 24 months) give 0.933; with the example's own day and half-life it is 0.936
    const f = join(dir, 'd.json'); writeFileSync(f, JSON.stringify(r.credential));
    expect(conf(spawnSync('ruby', [rubyScript, f, '--allow-unpinned'], { encoding: 'utf8' }))).toBe(0.933);
    expect(r.engine.verifyCredential(r.credential, { policy: pol('2026-03-12') ? { ...pol('2026-03-12'), halfLifeMonths: 24 } : null }).recognition.confidence).toBe(0.933);
  });
});

describe('E3: both cross-checkers can pin the issuer and the log key, and refuse to say OK without pins', () => {
  const real = runExample('maths-oral').credential;
  const stranger = twoOnOneLog({ issuerSeed: 77, logSeed: 78 }).first; // internally perfect, signed by someone else's engine
  const pinsOf = (c) => ['--issuer', c.issuer, '--log-key', c.sanad.log.logKey];
  it.skipIf(!have)('Python', () => {
    expect(runPinned(real, pinsOf(real)).status).toBe(0);
    const noPins = spawnSync('python3', [script, join(dir, 'p.json'), '--as-of', '2026-03-03'], { encoding: 'utf8' });
    expect(noPins.status).toBe(1); expect(noPins.stdout).toMatch(/FAIL pins/); expect(noPins.stdout).not.toMatch(/failures: 0/);
    const forged = runPinned(stranger, pinsOf(real));
    expect(forged.status).toBe(1); expect(forged.stdout).toMatch(/FAIL pin-issuer/); expect(forged.stdout).toMatch(/FAIL pin-log-key/);
    expect(run(stranger).status).toBe(0); // unpinned and explicitly allowed: internally consistent
  });
  it.skipIf(rb.status !== 0)('Ruby', () => {
    expect(runRb(real, '2026-03-03', pinsOf(real)).stdout).toMatch(/OVERALL: PASS/);
    const noPins = runRb(real, '2026-03-03', []); expect(noPins.stdout).toMatch(/OVERALL: FAIL/); expect(noPins.stdout).toMatch(/FAIL\s+pins/); expect(noPins.status).toBe(1);
    const forged = runRb(stranger, '2026-03-03', pinsOf(real)); expect(forged.stdout).toMatch(/OVERALL: FAIL/); expect(forged.stdout).toMatch(/FAIL\s+pin-issuer/); expect(forged.stdout).toMatch(/FAIL\s+pin-log-key/);
  });
  it.skipIf(!have)('Python ends in a FAIL line, not a traceback, when an attestation names another key', () => {
    const bad = JSON.parse(JSON.stringify(real)); bad.sanad.bundle.attestations[0].attestor = real.sanad.bundle.attestations[1].attestor;
    const o = run(bad);
    expect(o.stderr).not.toMatch(/Traceback/); expect(o.stdout).toMatch(/FAIL/); expect(o.status).toBe(1);
    const weird = JSON.parse(JSON.stringify(real)); weird.sanad.bundle.attestations[0].signature = 'not-a-jws';
    const w = run(weird); expect(w.stderr).not.toMatch(/Traceback/); expect(w.status).toBe(1);
    const odd = JSON.parse(JSON.stringify(real)); delete odd.sanad.log;
    const x = run(odd); expect(x.stderr).not.toMatch(/Traceback/); expect(x.stdout).toMatch(/FAIL/); expect(x.status).toBe(1);
  });
});
