#!/usr/bin/env node
// Runs every conformance vector against the reference implementation and prints pass or fail with the rule identifiers of the explanation.
//   node reference/verify.mjs [path/to/vectors.json]      exit code 0 if every vector passes
// An independent implementation conforms when it gives the same result on every vector (see /conformance/ on the website).
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(new URL(import.meta.url).pathname);
const lib = await import(pathToFileURL(join(here, 'dist/sanad-reference.mjs')).href);
const file = process.argv[2] ?? join(here, 'vectors.json');
const data = JSON.parse(readFileSync(file, 'utf8'));
const { recognise, sealCredential, applyTamper, infer, SANAD_VERSION } = lib;
const build = (v) => { const c = sealCredential(v.credential); return v.tamper ? applyTamper(c, v.tamper) : c; };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
let pass = 0, fail = 0;
const report = (ok, id, name, detail) => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${name}${detail ? '\n      ' + detail : ''}`); };
console.log(`Sanad reference verifier, algorithm ${SANAD_VERSION}, vectors: ${file}\n`);
for (const v of data.vectors) {
  try {
    const r = recognise(build(v), v.policy); const e = v.expect; const problems = [];
    if (r.version !== SANAD_VERSION) problems.push('version ' + r.version);
    if (r.status !== e.status) problems.push(`status ${r.status} (expected ${e.status})`);
    if (r.level !== e.level) problems.push(`level ${r.level} (expected ${e.level})`);
    if (r.attestedLevel !== e.attestedLevel) problems.push(`attestedLevel ${r.attestedLevel} (expected ${e.attestedLevel})`);
    if (Math.abs(r.confidence - e.confidence) > 0.0005) problems.push(`confidence ${r.confidence} (expected ${e.confidence})`);
    if (!same(r.dropped.map((d) => [d.id, d.rule]).sort(), [...e.dropped].sort())) problems.push('dropped items differ');
    const seen = new Set(r.explanation.map((s) => s.rule)); for (const rule of e.rules) if (!seen.has(rule)) problems.push(`rule ${rule} missing from the explanation`);
    report(problems.length === 0, v.id, v.name, `status=${r.status} level=${r.level} confidence=${r.confidence} rules=${r.explanation.map((s) => s.rule).join(',')}${problems.length ? ' :: ' + problems.join('; ') : ''}`);
  } catch (err) { report(false, v.id, v.name, String(err.message ?? err)); }
}
for (const t of data.inference ?? []) {
  try {
    const g = { requires: (id) => t.graph.requires[id] ?? [] }; const out = infer(g, t.skill, t.level, t.confidence, t.policy, t.direct);
    const got = out.map((o) => [o.skill, o.level, o.confidence, o.distance, o.path]);
    report(same(got, t.expect) && out.every((o) => o.inferred === true), t.id, t.name, got.map((x) => `${x[0]}@${x[1]}`).join(' ') || '(none)');
  } catch (err) { report(false, t.id, t.name, String(err.message ?? err)); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
