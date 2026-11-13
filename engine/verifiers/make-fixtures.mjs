// Writes engine/verifiers/fixtures/<case>/: an exported static directory (the tree a mirror would serve), case.json (what the verifier chooses: pins,
// policy, requirements, evaluation time) and expected.json (what the engine's verifier reports). Used to compare independent verifiers: node engine/verifiers/make-fixtures.mjs
// The keys are fixed seeds and the clock is fixed; nonces are random, so regenerating changes the hashes but not the expectations.
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as H from '../test/helpers.mjs';
import {
  createEngine, createMemoryStore, makeSigner, keyPairFromSeed, base58btcEncode, signIdentityAssurance, buildBundleFiles, writeFiles, publishCheckpoint, runWitness,
  verifyBundleFiles, DID_UPDATE_TYP, signJws, readTree,
} from '../src/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, 'fixtures');
const NOW = '2026-03-02T00:00:00.000Z';
const POLICY = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8, asOf: '2026-03-02' };
const STATUS_URL = 'https://example.org/sanad/status/revocation.json';
const hex = (c) => c.repeat(64);
const sha = (t) => createHash('sha256').update(t).digest('hex');
const mb = (signer) => 'z' + base58btcEncode(signer.publicKey);
const seedKey = (n, did) => makeSigner(keyPairFromSeed(H.seedOf(n)).privateKey, did);

function makeWorld({ tpl, webAttestor = false } = {}) {
  const issuer = seedKey(1), logSigner = seedKey(2);
  const clock = H.makeClock();
  const engine = createEngine({ store: createMemoryStore(), issuer, logSigner, clock, status: { url: STATUS_URL } });
  engine.registerTemplate(tpl ?? H.template());
  const people = {};
  for (const [i, n] of ['A', 'B', 'C'].entries()) people[n] = H.setup().people[n] && { name: n, signer: seedKey(10 + i), did: seedKey(10 + i).did };
  let web = null;
  if (webAttestor) {
    // C is a did:web identity that rotated: the first key is revoked from 2026-03-01 and the second key signs
    const c1 = seedKey(20, 'did:web:examiner.example'), c2key = keyPairFromSeed(H.seedOf(21)).privateKey;
    engine.registerDid({ id: c1.did, versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: mb(c1) }], revoked: [] }] });
    const c2pub = makeSigner(c2key).publicKey;
    const version = { version: 2, validFrom: '2026-03-01', keys: [{ id: '#k1', publicKeyMultibase: mb(c1) }, { id: '#k2', publicKeyMultibase: 'z' + base58btcEncode(c2pub) }], revoked: [{ id: '#k1', from: '2026-03-01' }] };
    engine.updateDid(c1.did, version, c1.sign(DID_UPDATE_TYP, { did: c1.did, ...version }));
    const kid = c1.did + '#k2';
    web = { did: c1.did, signer: { did: c1.did, kid, publicKey: c2pub, sign: (typ, payload) => signJws({ typ, kid, payload, privateKey: c2key }) }, pinned: 'z' + base58btcEncode(c2pub) };
    people.C = { name: 'C', signer: web.signer, did: web.did };
  }
  return { engine, issuer, logSigner, clock, people, web };
}

function issue(w, id, { levels = { A: 4, B: 4 }, body, identity, who = ['A', 'B'] } = {}) {
  H.newAssessment(w.engine, { id });
  if (body || identity) w.engine.addEvidence(id, { key: 'E1', body: { ...(body ?? {}), ...(identity ? { identityAssurance: identity } : {}) } });
  const inv = who.map((n) => w.engine.invite(id, { attestor: w.people[n].did, role: 'examiner', evidence: 'E1' }));
  const sec = inv.map((i, k) => H.commitAs(w.engine, { signer: w.people[who[k]].signer }, id, i.attestationId, levels[who[k]]).secret);
  sec.forEach((x, k) => H.revealAs(w.engine, { signer: w.people[who[k]].signer }, id, x));
  return w.engine.finalize(id);
}

const sitting = (id, ident) => ({ sittingId: 'sit-' + id, paperFingerprint: hex('a'), strokeLogHead: hex('b'), recordingSha256: hex('c'), recordingCipherSha256: hex('d'), recordingBytes: 52428800, publication: { scope: 'hashes', date: '2026-03-01', url: 'https://example.org/sanad/' }, ...(ident ? {} : {}) });
const identity = (w, sittingId, level) => signIdentityAssurance({ signer: seedKey(30), sittingId, level, method: 'document-on-camera', date: '2026-03-01', candidateKey: mb(seedKey(40)) });

const cases = [];
const add = (name, description, build) => cases.push({ name, description, build });

add('honest-full', 'Two examiners, full sitting evidence with identity level A1, status list (clear), one witness cosigned a later checkpoint. Everything passes.', async () => {
  const w = makeWorld(); const id = 'as-1';
  const cred = issue(w, id, { body: sitting(id), identity: identity(w, 'sit-' + id, 'A1') });
  issue(w, 'as-2'); w.clock.advance(1000);
  const pub = join(OUT, '_tmp-pub'), wd = join(OUT, '_tmp-wit'); rmSync(pub, { recursive: true, force: true }); rmSync(wd, { recursive: true, force: true });
  publishCheckpoint({ engine: w.engine, dir: pub });
  const wit = seedKey(50);
  await runWitness({ source: pub, outDir: wd, signer: wit, logKey: w.logSigner.did, now: w.clock.now() });
  const b = buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, base: 'https://example.org/sanad', checkpointsDir: pub, witnessDirs: [wd], now: w.clock.now() });
  rmSync(pub, { recursive: true, force: true }); rmSync(wd, { recursive: true, force: true });
  return { w, files: b.files, options: { minIdentityLevel: 'A1', requireWitnesses: 1, trustedWitnesses: [wit.did], requireStatus: true } };
});
add('honest-plain', 'Two examiners, a sitting with only minutes in its body (no schema members): passes with a warning.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1');
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: {} };
});
add('disagreeing-examiners', 'Levels 5 and 2: the spread above one halves the weights (R7); level is the lower median.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1', { levels: { A: 5, B: 2 } });
  return { w, files: buildBundleFiles({ engine: w.engine, credentials: undefined, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: {} };
});
add('revoked', 'The issuer revoked the credential: the status list has the bit set.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1'); w.engine.revokeCredential(cred.id, { reason: 'issued in error' });
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: { requireStatus: true } };
});
add('did-web-rotation-pinned', 'Examiner C is a did:web identity whose first key was revoked before the sitting; the credential embeds the history; the verifier pinned the current key.', async () => {
  const w = makeWorld({ webAttestor: true }); const cred = issue(w, 'as-1', { levels: { A: 4, C: 4 }, who: ['A', 'C'] });
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: { pinnedKeys: { [w.web.did]: [w.web.pinned] } } };
});
add('did-web-rotation-unpinned', 'The same credential, but the verifier pinned no key for the did:web examiner: the embedded history is only the issuer\'s claim.', async () => {
  const w = makeWorld({ webAttestor: true }); const cred = issue(w, 'as-1', { levels: { A: 4, C: 4 }, who: ['A', 'C'] });
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: {} };
});
add('wrong-issuer-pin', 'The verifier pinned another issuer DID.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1');
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: { trustedIssuers: [seedKey(99).did] } };
});
add('identity-below-required', 'Identity assurance A1 recorded; the verifier requires A2.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1', { body: sitting('as-1'), identity: identity(w, 'sit-as-1', 'A1') });
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: { minIdentityLevel: 'A2' } };
});
add('strict-policy', 'A policy asking for three attestors over a two-examiner credential: provisional.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1');
  return { w, files: buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() }).files, options: { policy: { ...POLICY, minAttestors: 3 } } };
});
add('tampered-file', 'evidence.json was edited after export: the manifest hash no longer matches.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1'); const b = buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() });
  const k = 'bundles/' + b.bundleHash + '/evidence.json'; b.files.set(k, b.files.get(k).replace('Oral sitting', 'Oral sittinG'));
  return { w, files: b.files, options: {} };
});
add('tampered-mark', 'A mark in the credential was changed from 3 to 5 and every manifest hash recomputed: the issuer signature, the bundle hash and the attestor signature all fail.', async () => {
  const w = makeWorld(); const cred = issue(w, 'as-1', { levels: { A: 4, B: 3 } }); const b = buildBundleFiles({ engine: w.engine, credentialId: cred.id, issuerSigner: w.issuer, now: w.clock.now() });
  const d = 'bundles/' + b.bundleHash + '/';
  const c = JSON.parse(b.files.get(d + 'credential.json')); c.sanad.bundle.attestations[1].level = 5;
  const att = JSON.parse(b.files.get(d + 'attestations.json')); att[1].level = 5;
  b.files.set(d + 'credential.json', JSON.stringify(c, null, 2) + '\n'); b.files.set(d + 'attestations.json', JSON.stringify(att, null, 2) + '\n');
  const m = JSON.parse(b.files.get(d + 'manifest.json'));
  for (const n of Object.keys(m.files)) m.files[n] = sha(b.files.get(d + n));
  b.files.set(d + 'manifest.json', JSON.stringify(m, null, 2) + '\n');
  return { w, files: b.files, options: {} };
});

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
for (const c of cases) {
  const { w, files, options } = await c.build();
  const dir = join(OUT, c.name);
  writeFiles(join(dir, 'tree'), files);
  const opts = {
    policy: POLICY, trustedIssuers: [w.issuer.did], trustedLogKeys: [w.logSigner.did], diagnose: true, now: Date.parse(NOW), ...options,
  };
  const r = verifyBundleFiles(readTree(join(dir, 'tree')), opts);
  const caseJson = { name: c.name, description: c.description, evaluatedAt: NOW, options: { ...opts, now: undefined, diagnose: undefined } };
  writeFileSync(join(dir, 'case.json'), JSON.stringify(caseJson, null, 2) + '\n');
  const rec = r.recognition;
  writeFileSync(join(dir, 'expected.json'), JSON.stringify({
    ok: r.ok, checks: r.checks.map((x) => ({ name: x.name, ok: x.ok })), warnings: r.warnings.length,
    recognition: rec ? { status: rec.status, level: rec.level, attestedLevel: rec.attestedLevel, confidence: rec.confidence, dropped: rec.dropped.map((d) => d.id + ':' + d.rule), unverified: rec.unverified === true } : null,
  }, null, 2) + '\n');
  console.log((r.ok ? 'ok   ' : 'FAIL ') + c.name + (r.ok ? '' : '  failed: ' + r.checks.filter((x) => !x.ok).map((x) => x.name).join(',')));
}
