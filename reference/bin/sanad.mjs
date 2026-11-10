#!/usr/bin/env node
// sanad: the core command line.
//   sanad run-vectors [vectors.json]                     run the conformance vectors (exit code 0 if all pass)
//   sanad verify <credential.json> [--policy <file>]     run the recognition function on a core credential (or the bundle inside a credential document)
// `verify` checks hashes, commitments and the chain (R1) and applies the policy; it does not check Ed25519 signatures. Use `sanad-engine verify` for that.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runVectors } from '../run.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const lib = await import(pathToFileURL(join(here, '../dist/sanad-reference.mjs')).href);
const [cmd, ...rest] = process.argv.slice(2);
const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'));
const usage = 'usage: sanad run-vectors [vectors.json] | sanad verify <credential.json> [--policy <policy.json>]';

if (cmd === 'run-vectors') {
  const file = rest[0] ?? join(here, '../vectors.json');
  let pass = 0, fail = 0;
  for (const r of runVectors(lib, readJson(file))) { r.ok ? pass++ : fail++; console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}${r.problems.length ? ' :: ' + r.problems.join('; ') : ''}`); }
  console.log(`\n${pass} passed, ${fail} failed (algorithm ${lib.SANAD_VERSION})`);
  process.exit(fail ? 1 : 0);
} else if (cmd === 'verify' && rest[0]) {
  const doc = readJson(rest[0]);
  const cred = doc?.sanad?.bundle ?? doc;
  const pf = flag('--policy'); const base = pf ? readJson(pf) : (doc?.sanad?.policy ?? lib.DEFAULT_POLICY);
  const policy = { ...lib.DEFAULT_POLICY, ...base }; delete policy.id;
  const r = lib.recognise(cred, policy);
  console.log(`Sanad core verifier, algorithm ${r.version}. Signatures are NOT checked by this command.`);
  console.log(`skill ${r.skill}: status ${r.status}, level ${r.level}, confidence ${r.confidence}`);
  for (const s of r.explanation) console.log(`  ${s.rule}  ${s.summary}`);
  process.exit(r.dropped.some((d) => d.rule === 'R1') ? 2 : 0);
} else { console.error(usage); process.exit(64); }
