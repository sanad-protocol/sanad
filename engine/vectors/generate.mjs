// Writes engine/vectors/engine-*.json from the scenarios below, filling each step's `expect` from a run of this implementation.
// Review the diff by hand before committing: node engine/vectors/generate.mjs
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runVector } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SUBJECT = 'urn:uuid:11111111-1111-4111-8111-111111111111';
const template = {
  id: 'maths-oral-v1', version: 1, title: 'Maths oral', skill: { id: 'analysis.limits', title: 'Limits' },
  levels: [0, 1, 2, 3, 4, 5].map((level) => ({ level, label: 'L' + level })),
  evidence: [{ key: 'E1', kind: 'sitting', summary: 'Oral sitting' }],
  attestors: { min: 2, max: 3, roles: ['examiner'] }, liveSitting: true, deadlines: { commitHours: 24, revealHours: 48 },
  policy: { id: 'p1', minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8 },
};
const assessment = { id: 'as-1', templateId: template.id, subject: SUBJECT, claimedLevel: 4, evidence: [{ key: 'E1', date: '2026-03-01', summary: 'Oral sitting of 40 minutes', body: { minutes: 40 } }] };
const setup = (people, over = {}) => ({ clock: '2026-03-01T09:00:00.000Z', template, assessment, people, ...over });
const P = { A: { seed: 10 }, B: { seed: 11 }, C: { seed: 12 } };
const N = (c) => c.repeat(22); // fixed nonces, 22 characters of the base64url alphabet
const inv = (who) => ({ op: 'invite', who, role: 'examiner', evidence: 'E1' });

const vectors = [
  { id: 'engine-commit-reveal', description: 'Honest run with two examiners. Also checks that a reveal before all commits is refused, that a commit cannot be copied from another attestor or sent twice, and that the credential verifies with every check true.', setup: setup({ A: P.A, B: P.B }), steps: [
    inv('A'), inv('B'),
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 4, nonce: N('a') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' },
    { op: 'commit', who: 'B', att: 'as-1.a02', copyFrom: 'as-1.a01' },
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 4, nonce: N('a') },
    { op: 'commit', who: 'B', att: 'as-1.a02', level: 3, nonce: N('b') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' },
    { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'finalize' },
    { op: 'verify' },
    { op: 'verify', policy: { minAttestors: 3, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8 } },
  ] },
  { id: 'engine-tamper', description: 'After sealing: a changed mark, a changed signature only, and a changed evidence kind are each caught; a changed mark drops that attestation under R1 for the verifier.', setup: setup({ A: P.A, B: P.B }), steps: [
    inv('A'), inv('B'),
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 4, nonce: N('a') }, { op: 'commit', who: 'B', att: 'as-1.a02', level: 3, nonce: N('b') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' }, { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'finalize' },
    { op: 'verify', tamper: [{ attestation: 'as-1.a02', set: { level: 5 } }] },
    { op: 'verify', flipSignatureOf: 'as-1.a02' },
    { op: 'verify', tamper: [{ evidence: 'as-1.E1', set: { kind: 'peer' } }] },
  ] },
  { id: 'engine-late-reveal', description: 'B commits but reveals after revealBy: refused as late and recorded; the credential holds A only and the verifier under minAttestors 2 gets a provisional result.', setup: setup({ A: P.A, B: P.B }), steps: [
    inv('A'), inv('B'),
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 4, nonce: N('a') }, { op: 'commit', who: 'B', att: 'as-1.a02', level: 3, nonce: N('b') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' },
    { op: 'advance', hours: 80 },
    { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-04' },
    { op: 'finalize' },
    { op: 'verify' },
  ] },
  { id: 'engine-missing-reveal', description: 'C commits and never reveals: C is listed as missing and a missing-reveal leaf is logged; finalize is refused before the deadline and allowed after it.', setup: setup({ A: P.A, B: P.B, C: P.C }), steps: [
    inv('A'), inv('B'), inv('C'),
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 4, nonce: N('a') }, { op: 'commit', who: 'B', att: 'as-1.a02', level: 4, nonce: N('b') }, { op: 'commit', who: 'C', att: 'as-1.a03', level: 1, nonce: N('c') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' }, { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'finalize' },
    { op: 'advance', hours: 100 },
    { op: 'finalize' },
    { op: 'verify' },
  ] },
  { id: 'engine-duplicate-attestor', description: 'The same attestor cannot be invited twice on one evidence item, the subject cannot attest, an unknown role is refused, and the template maximum is enforced.', setup: setup({ A: P.A, B: P.B, C: P.C, D: { seed: 13 } }), steps: [
    inv('A'), inv('A'),
    { op: 'invite', who: 'B', attestorDid: SUBJECT, role: 'examiner', evidence: 'E1' },
    { op: 'invite', who: 'B', role: 'judge', evidence: 'E1' },
    inv('B'), inv('C'), inv('D'),
  ] },
  { id: 'engine-key-rotation', description: 'Examiners X and Y hold did:web identities. Y rotates before committing: a commit signed with the revoked #k1 is refused, one signed with #k2 is accepted. X commits under #k1, then rotates with #k1 revoked from 2026-03-03: a reveal dated 2026-03-03 signed with #k1 is refused, a reveal dated 2026-03-02 signed with #k1 is accepted (the key was valid on that date). The credential verifies.', setup: setup({ A: P.A, X: { seed: 20, did: 'did:web:x.example' }, Y: { seed: 22, did: 'did:web:y.example' } }), steps: [
    { op: 'registerDid', who: 'X', validFrom: '2026-01-01' }, { op: 'registerDid', who: 'Y', validFrom: '2026-01-01' },
    inv('A'), inv('X'), inv('Y'),
    { op: 'rotateDid', who: 'Y', newSeed: 23, newName: 'Y2', validFrom: '2026-03-01', revokeFrom: '2026-03-01' },
    { op: 'commit', who: 'Y', att: 'as-1.a03', level: 3, nonce: N('y') },
    { op: 'commit', who: 'Y2', att: 'as-1.a03', level: 3, nonce: N('y') },
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 3, nonce: N('a') },
    { op: 'commit', who: 'X', att: 'as-1.a02', level: 4, nonce: N('x') },
    { op: 'rotateDid', who: 'X', newSeed: 21, newName: 'X2', validFrom: '2026-03-03', revokeFrom: '2026-03-03' },
    { op: 'advance', hours: 48 },
    { op: 'reveal', who: 'X', att: 'as-1.a02', date: '2026-03-03' },
    { op: 'reveal', who: 'X', att: 'as-1.a02', date: '2026-03-02' },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-03' },
    { op: 'reveal', who: 'Y2', att: 'as-1.a03', date: '2026-03-03' },
    { op: 'finalize' },
    { op: 'verify' },
  ] },
  { id: 'engine-invitation-removed', description: 'An invitation is withdrawn before the first commit: the attestation id a01 is never reused (the next invitation is a03), a removed attestor can neither get a ticket nor commit, removal is refused once that attestor has committed, and the credential lists the removal under process.removed.', setup: setup({ A: P.A, B: P.B, C: P.C }), steps: [
    inv('A'), inv('B'),
    { op: 'removeInvitation', att: 'as-1.a01' },
    { op: 'removeInvitation', att: 'as-1.a01' },
    inv('C'),
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 2, nonce: N('a') },
    { op: 'commit', who: 'B', att: 'as-1.a02', level: 3, nonce: N('b') },
    { op: 'removeInvitation', att: 'as-1.a02' },
    { op: 'commit', who: 'C', att: 'as-1.a03', level: 3, nonce: N('c') },
    { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'reveal', who: 'C', att: 'as-1.a03', date: '2026-03-01' },
    { op: 'finalize' },
    { op: 'removeInvitation', att: 'as-1.a03' },
    { op: 'verify' },
  ] },
  { id: 'engine-preview-ticket', description: 'The provider time and day, a signing ticket (commit through the ticket alone), and a recognition preview that reads only revealed attestations: with one reveal of two the preview uses a01 only and reports one pending; the final result differs.', setup: setup({ A: P.A, B: P.B }), steps: [
    { op: 'info' },
    inv('A'), inv('B'),
    { op: 'ticket', who: 'A', att: 'as-1.a01' },
    { op: 'commit', who: 'A', att: 'as-1.a01', level: 5, nonce: N('a'), viaTicket: true },
    { op: 'preview' },
    { op: 'commit', who: 'B', att: 'as-1.a02', level: 1, nonce: N('b'), viaTicket: true },
    { op: 'preview' },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' },
    { op: 'preview' },
    { op: 'preview', policy: { minAttestors: 1, requireLive: false, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 } },
    { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'finalize' },
  ] },
  { id: 'engine-native-level-map', description: 'The template has a levelMap (host grades g1..g6 to levels 0..5). A native mark g5 gives level 4 and is carried inside the nonce, hidden until the reveal; a second attestor sends a plain level. The credential keeps the native mark in the revealed nonce.', setup: setup({ A: P.A, B: P.B }, { template: { ...template, levelMap: { g1: 0, g2: 1, g3: 2, g4: 3, g5: 4, g6: 5 } } }), steps: [
    inv('A'), inv('B'),
    { op: 'commit', who: 'A', att: 'as-1.a01', native: 'g5', nonce: 'nm-g5-' + 'k'.repeat(22) },
    { op: 'commit', who: 'B', att: 'as-1.a02', level: 3, nonce: N('b') },
    { op: 'reveal', who: 'A', att: 'as-1.a01', date: '2026-03-01' },
    { op: 'reveal', who: 'B', att: 'as-1.a02', date: '2026-03-01' },
    { op: 'finalize' },
    { op: 'verify' },
  ] },
];

for (const v of vectors) {
  for (const s of v.steps) delete s.expect;
  const res = runVector(v);
  v.steps.forEach((s, i) => { s.expect = res[i].observed; });
  writeFileSync(join(here, v.id + '.json'), JSON.stringify(v, null, 2) + '\n');
  console.log('wrote ' + v.id);
}
