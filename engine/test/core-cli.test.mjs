import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runExample } from '../examples/run.mjs';

const bin = fileURLToPath(new URL('../../reference/bin/sanad.mjs', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'core-cli-'));
const doc = join(dir, 'c.json'); writeFileSync(doc, JSON.stringify(runExample('maths-oral').credential));
const POL = { minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8 };
const run = (...a) => spawnSync('node', [bin, 'verify', doc, ...a], { encoding: 'utf8' });

describe('core command sanad verify (review 2, M1)', () => {
  it('refuses to run without a policy, and never fills a partial policy', () => {
    const none = run(); expect(none.status).toBe(64); expect(none.stderr).toMatch(/complete policy/);
    const pf = join(dir, 'partial.json'); writeFileSync(pf, JSON.stringify({ minAttestors: 2 }));
    const partial = run('--policy', pf, '--as-of', '2026-03-03'); expect(partial.status).toBe(64); expect(partial.stderr).toMatch(/policy refused.*halfLifeMonths/);
  });
  it('needs an evaluation day: a policy without asOf and without --as-of is refused instead of defaulting to a date that could drop evidence', () => {
    const pf = join(dir, 'full.json'); writeFileSync(pf, JSON.stringify(POL));
    const r = run('--policy', pf); expect(r.status).toBe(64); expect(r.stderr).toMatch(/asOf/);
    const ok = run('--policy', pf, '--as-of', '2026-03-03'); expect(ok.status).toBe(0); expect(ok.stdout).toMatch(/your policy; evaluation day 2026-03-03/); expect(ok.stdout).toMatch(/status recognised/);
  });
  it('the issuer\'s recommendation is used only on request and is labelled loudly; the output carries the experimental notice and says signatures are not checked', () => {
    const r = run('--use-issuer-policy'); expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/THE ISSUER'S RECOMMENDED POLICY \(not a verifier policy\)/); expect(r.stdout).toMatch(/EXPERIMENTAL: not cryptographically reviewed/); expect(r.stdout).toMatch(/Signatures are NOT checked/);
  });
  it('exit code 2 when an item failed integrity', () => {
    const bad = JSON.parse(JSON.stringify(runExample('maths-oral').credential)); bad.sanad.bundle.attestations[0].level = 5;
    const f = join(dir, 'bad.json'); writeFileSync(f, JSON.stringify(bad));
    expect(spawnSync('node', [bin, 'verify', f, '--use-issuer-policy'], { encoding: 'utf8' }).status).toBe(2);
  });
});
