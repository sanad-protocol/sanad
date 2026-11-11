#!/usr/bin/env node
// sanad: the core command line.
//   sanad run-vectors [vectors.json]                     run the conformance vectors (exit code 0 if all pass)
//   sanad verify <credential.json> --policy <file> [--as-of <day>]   run the recognition function on a core credential (or the bundle inside a credential document)
//   sanad verify <credential.json> --use-issuer-policy [--as-of <day>]   knowingly use an engine credential's recommended policy (labelled)
// Exit code: 0 on a result, also when nothing is recognised; 2 when any item failed integrity (R1); 64 for usage or a refused policy.
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
const usage = 'usage: sanad run-vectors [vectors.json] | sanad verify <credential.json> (--policy <policy.json> [--as-of <day>] | --use-issuer-policy [--as-of <day>])';

if (cmd === 'run-vectors') {
  const file = rest[0] ?? join(here, '../vectors.json');
  let pass = 0, fail = 0;
  for (const r of runVectors(lib, readJson(file))) { r.ok ? pass++ : fail++; console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}${r.problems.length ? ' :: ' + r.problems.join('; ') : ''}`); }
  console.log(`\n${pass} passed, ${fail} failed (algorithm ${lib.SANAD_VERSION})`);
  process.exit(fail ? 1 : 0);
} else if (cmd === 'verify' && rest[0]) {
  // The verifier states its own complete policy and evaluation day. Nothing is filled in from defaults; the issuer's recommendation is used only on request and is labelled.
  const doc = readJson(rest[0]);
  const cred = doc?.sanad?.bundle ?? doc;
  const pf = flag('--policy'); const asOf = flag('--as-of'); const useIssuer = rest.includes('--use-issuer-policy');
  let policy; let label;
  if (pf) { policy = { ...readJson(pf) }; label = 'your policy'; if (asOf !== undefined) policy.asOf = asOf; }
  else if (useIssuer && doc?.sanad?.policy) {
    policy = { ...doc.sanad.policy }; delete policy.id;
    policy.asOf = asOf ?? (typeof doc.validFrom === 'string' ? doc.validFrom.slice(0, 10) : undefined);
    label = 'THE ISSUER\'S RECOMMENDED POLICY (not a verifier policy)' + (asOf ? '' : ', with the credential date as the evaluation day');
  } else { console.error('verify needs a complete policy: --policy <file> (all seven fields; asOf in the file or --as-of), or --use-issuer-policy for an engine credential document.\n' + usage); process.exit(64); }
  const problems = lib.policyProblems(policy);
  if (problems.length) { console.error('policy refused: ' + problems.join('; ')); process.exit(64); }
  const r = lib.recognise(cred, policy);
  console.log(`Sanad core verifier, algorithm ${r.version}. EXPERIMENTAL: not cryptographically reviewed. Signatures are NOT checked by this command (use sanad-engine verify); the result is UNVERIFIED as to who signed what.`);
  console.log(`policy: ${label}; evaluation day ${policy.asOf}`);
  console.log(`skill ${r.skill}: status ${r.status}, level ${r.level}, confidence ${r.confidence}`);
  for (const s of r.explanation) console.log(`  ${s.rule}  ${s.summary}`);
  // exit code: 2 when any item failed integrity (R1); 0 otherwise, also when nothing is recognised: read the status line.
  process.exit(r.dropped.some((d) => d.rule === 'R1') ? 2 : 0);
} else { console.error(usage); process.exit(64); }
