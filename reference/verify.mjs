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
import { runVectors } from './run.mjs';
let pass = 0, fail = 0;
console.log(`Sanad reference verifier, algorithm ${lib.SANAD_VERSION}, vectors: ${file}\n`);
for (const r of runVectors(lib, data)) {
  r.ok ? pass++ : fail++;
  const detail = r.kind === 'recognition' ? `status=${r.status} level=${r.level} confidence=${r.confidence} rules=${(r.rules ?? []).join(',')}` : r.summary;
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}\n      ${detail ?? ''}${r.problems.length ? ' :: ' + r.problems.join('; ') : ''}`);
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
