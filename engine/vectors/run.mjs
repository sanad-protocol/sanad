// Runs every engine-*.json vector: node engine/vectors/run.mjs   (exit code 0 only if all steps match their `expect`)
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runVector } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
export function runAll() {
  const out = [];
  for (const f of readdirSync(here).filter((n) => /^engine-.*\.json$/.test(n)).sort()) {
    const v = JSON.parse(readFileSync(join(here, f), 'utf8'));
    const res = runVector(v);
    const bad = res.filter((r) => !r.ok || v.steps[r.i].expect === undefined);
    out.push({ id: v.id, file: f, steps: res.length, ok: bad.length === 0, bad: bad.map((r) => ({ step: r.i, op: r.op, observed: r.observed, expected: v.steps[r.i].expect })) });
  }
  return out;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let fail = 0;
  const all = runAll();
  for (const r of all) { console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  (${r.steps} steps)`); if (!r.ok) { fail++; console.log(JSON.stringify(r.bad, null, 1)); } }
  console.log(`\n${all.length - fail} passed, ${fail} failed`);
  process.exit(fail || all.length === 0 ? 1 : 0);
}
