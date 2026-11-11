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
const run = (doc, asOf = '2026-03-03') => { const f = join(dir, 'c.json'); writeFileSync(f, JSON.stringify(doc)); return spawnSync('python3', [script, f, '-', asOf], { encoding: 'utf8' }); };

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
const runRb = (doc, asOf = '2026-03-03') => { const f = join(dir, 'r.json'); writeFileSync(f, JSON.stringify(doc)); return spawnSync('ruby', [rubyScript, f, asOf, '36'], { encoding: 'utf8' }); };

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

