import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import * as H from './helpers.mjs';
import { buildBundleFiles, writeFiles, readBundlePath, readTree, verifyBundleFiles, publishCheckpoint, runWitness, verifyWitnesses, makeCosignature, readWitnessDir, makeSigner, keyPairFromSeed, createResolver } from '../src/index.mjs';

const root = mkdtempSync(join(tmpdir(), 'sanad-export-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let n = 0;
const fresh = () => { const d = join(root, 'd' + n++); return d; };

function world(count = 2) {
  const s = H.setup(); const { engine, people: P } = s;
  const docs = [];
  for (let k = 1; k <= count; k++) {
    const id = 'as-' + k;
    H.newAssessment(engine, { id });
    const inv = ['A', 'B'].map((x) => engine.invite(id, { attestor: P[x].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, j) => H.commitAs(engine, P['AB'[j]], id, i.attestationId, 4).secret);
    sec.forEach((x, j) => H.revealAs(engine, P['AB'[j]], id, x));
    docs.push(engine.finalize(id));
  }
  return { ...s, docs };
}
const opts = (s, extra = {}) => ({ useRecommendedPolicy: true, trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did], ...extra });
const failedNames = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe('export', () => {
  it('writes the documented layout and the directory verifies offline', () => {
    const s = world(); const out = fresh();
    const { bundleHash, files } = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, base: 'https://example.org/sanad', now: s.clock.now() });
    writeFiles(out, files);
    expect(s.docs[0].evidence[0].id).toBe('urn:sanad:bundle:' + bundleHash);
    const dir = join(out, 'bundles', bundleHash);
    expect(readdirSync(dir).sort()).toEqual(['README.md', 'attestations.json', 'checkpoint.json', 'consistency.json', 'credential.json', 'dids.json', 'evidence.json', 'log.json', 'manifest.json']);
    expect(existsSync(join(out, 'issuer.json'))).toBe(true);
    expect(readFileSync(join(dir, 'README.md'), 'utf8')).toContain('https://example.org/sanad/bundles/<bundleHash>/');
    for (const path of [dir, out]) {
      const r = verifyBundleFiles(readBundlePath(path), opts(s));
      expect(r.ok, JSON.stringify(failedNames(r))).toBe(true);
      expect(r.checks.map((c) => c.name).slice(0, 4)).toEqual(['bundle-files', 'bundle-consistency', 'issuer-card', 'consistency-proofs']);
    }
  });
  it('a second credential on the same log verifies from its own directory', () => {
    const s = world(); const out = fresh();
    const b = buildBundleFiles({ engine: s.engine, credentialId: s.docs[1].id, issuerSigner: s.issuer, now: s.clock.now() });
    writeFiles(out, b.files);
    expect(verifyBundleFiles(readBundlePath(join(out, 'bundles', b.bundleHash)), opts(s)).ok).toBe(true);
  });
  it('refuses an issuer key that did not issue the credential', () => {
    const s = world();
    expect(() => buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.logSigner })).toThrow(/issued by/);
  });
  it('a changed, removed or extra file is caught', () => {
    const s = world();
    const { bundleHash, files } = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, now: s.clock.now() });
    const d = 'bundles/' + bundleHash + '/';
    const run = (mut) => { const m = new Map(files); mut(m); return verifyBundleFiles(m, opts(s)); };
    expect(failedNames(run((m) => m.set(d + 'evidence.json', m.get(d + 'evidence.json') + ' ')))).toContain('bundle-files');
    expect(failedNames(run((m) => m.delete(d + 'log.json')))).toContain('bundle-files');
    expect(failedNames(run((m) => m.delete(d + 'manifest.json')))).toContain('bundle-files');
    const extra = run((m) => m.set(d + 'notes.txt', 'x'));
    expect(extra.ok).toBe(true); expect(extra.warnings.join()).toMatch(/not listed/);
    expect(run((m) => m.delete('issuer.json')).warnings.join()).toMatch(/issuer card was not checked/);
  });
  it('a consistent re-hash of a changed split file is still caught against the credential', () => {
    const s = world();
    const { bundleHash, files } = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, now: s.clock.now() });
    const d = 'bundles/' + bundleHash + '/';
    const m = new Map(files);
    const ev = JSON.parse(m.get(d + 'evidence.json')); ev[0].summary = 'changed'; m.set(d + 'evidence.json', JSON.stringify(ev, null, 2) + '\n');
    const man = JSON.parse(m.get(d + 'manifest.json'));
    man.files['evidence.json'] = sha(m.get(d + 'evidence.json')); m.set(d + 'manifest.json', JSON.stringify(man, null, 2) + '\n');
    expect(failedNames(verifyBundleFiles(m, opts(s)))).toContain('bundle-consistency');
  });
  it('an issuer card signed by someone else, or naming another log, fails', () => {
    const s = world();
    const { bundleHash, files } = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, now: s.clock.now() });
    const card = JSON.parse(files.get('issuer.json'));
    const m1 = new Map(files); m1.set('issuer.json', JSON.stringify({ ...card, logId: 'other' }));
    expect(failedNames(verifyBundleFiles(m1, opts(s)))).toContain('issuer-card');
    const { proof, ...body } = card; const other = makeSigner(keyPairFromSeed(H.seedOf(88)).privateKey);
    const m2 = new Map(files); m2.set('issuer.json', JSON.stringify({ ...body, proof: { ...proof, jws: other.sign('sanad-issuer-card+jws', body) } }));
    expect(failedNames(verifyBundleFiles(m2, opts(s)))).toContain('issuer-card');
    expect(bundleHash).toHaveLength(64);
  });
  it('without pins the directory fails like the credential does', () => {
    const s = world();
    const { files } = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, now: s.clock.now() });
    const r = verifyBundleFiles(files, { useRecommendedPolicy: true });
    expect(failedNames(r)).toEqual(['trusted-issuer', 'trusted-log-key']);
  });
  it('a tree with several bundles needs one to be named', () => {
    const s = world(); const all = new Map();
    for (const d of s.docs) for (const [k, v] of buildBundleFiles({ engine: s.engine, credentialId: d.id, issuerSigner: s.issuer, now: s.clock.now() }).files) all.set(k, v);
    expect(verifyBundleFiles(all, opts(s)).checks[0].detail).toMatch(/several bundles/);
    expect(verifyBundleFiles(all, opts(s, { bundle: s.docs[0].evidence[0].bundleHash })).ok).toBe(true);
  });
  it('readTree skips dot directories and readBundlePath rejects other directories', () => {
    const d = fresh(); writeFiles(d, new Map([['a/b.txt', 'x']])); writeFiles(join(d, '.git'), new Map([['c', 'y']]));
    expect([...readTree(d).keys()]).toEqual(['a/b.txt']);
    expect(() => readBundlePath(d)).toThrow(/neither/);
    expect(() => writeFiles(d, new Map([['../x', 'y']]))).toThrow(/unsafe/);
  });
});

function sha(t) { return createHash('sha256').update(t).digest('hex'); }

describe('checkpoint publication', () => {
  it('publishes in order with a consistency proof to the previous checkpoint', () => {
    const s = world(1); const out = fresh();
    expect(publishCheckpoint({ engine: s.engine, dir: out })).toMatchObject({ published: true, size: s.engine.log.size() });
    const first = JSON.parse(readFileSync(join(out, 'checkpoints', 'latest.json'), 'utf8'));
    expect(first.previous).toBeNull();
    expect(publishCheckpoint({ engine: s.engine, dir: out })).toMatchObject({ published: false });
    // grow the log
    const P = s.people; H.newAssessment(s.engine, { id: 'as-9' });
    const inv = ['A', 'B'].map((x) => s.engine.invite('as-9', { attestor: P[x].did, role: 'examiner', evidence: 'E1' }));
    inv.forEach((i, j) => H.commitAs(s.engine, P['AB'[j]], 'as-9', i.attestationId, 3));
    s.clock.advance(60000);
    expect(publishCheckpoint({ engine: s.engine, dir: out, daily: true })).toMatchObject({ published: false });
    const r = publishCheckpoint({ engine: s.engine, dir: out });
    expect(r.published).toBe(true);
    const idx = JSON.parse(readFileSync(join(out, 'checkpoints', 'index.json'), 'utf8'));
    expect(idx.map((e) => e.size)).toEqual([first.checkpoint.payload.size, r.size]);
    const latest = JSON.parse(readFileSync(join(out, 'checkpoints', 'latest.json'), 'utf8'));
    expect(latest.previous.size).toBe(first.checkpoint.payload.size);
    expect(existsSync(join(out, 'checkpoints', r.size + '.json'))).toBe(true);
  });
  it('daily publishes again on a new UTC day, and entries are written on request', () => {
    const s = world(1); const out = fresh();
    publishCheckpoint({ engine: s.engine, dir: out, daily: true, entries: true });
    expect(JSON.parse(readFileSync(join(out, 'log', 'entries.json'), 'utf8'))).toHaveLength(s.engine.log.size());
    s.clock.advance(86400000 * 2);
    s.engine.log.append({ kind: 'bundle', ref: 'a'.repeat(64) });
    expect(publishCheckpoint({ engine: s.engine, dir: out, daily: true }).published).toBe(true);
  });
  it('refuses to publish a smaller or a forked log, and an empty one', () => {
    const s = world(1); const out = fresh();
    publishCheckpoint({ engine: s.engine, dir: out });
    const idxFile = join(out, 'checkpoints', 'index.json'); const idx = JSON.parse(readFileSync(idxFile, 'utf8'));
    idx[0].size += 5; writeFileSync(idxFile, JSON.stringify(idx));
    H.code(() => publishCheckpoint({ engine: s.engine, dir: out }), 'log_shrank');
    idx[0].size -= 5; idx[0].rootHash = 'f'.repeat(64); writeFileSync(idxFile, JSON.stringify(idx));
    H.code(() => publishCheckpoint({ engine: s.engine, dir: out }), 'log_forked');
    const e = H.setup();
    expect(publishCheckpoint({ engine: e.engine, dir: fresh() })).toMatchObject({ published: false });
  });
});

describe('witness', () => {
  const witnessSigner = (k) => makeSigner(keyPairFromSeed(H.seedOf(50 + k)).privateKey);
  const grow = (s, id) => {
    const P = s.people; H.newAssessment(s.engine, { id });
    const inv = ['A', 'B'].map((x) => s.engine.invite(id, { attestor: P[x].did, role: 'examiner', evidence: 'E1' }));
    inv.forEach((i, j) => H.commitAs(s.engine, P['AB'[j]], id, i.attestationId, 3));
    s.clock.advance(1000);
  };
  const codeOf = async (p) => { try { await p; } catch (e) { return e.code; } return null; };

  it('cosigns the first checkpoint, is idempotent, and follows growth through consistency proofs', async () => {
    const s = world(1); const pub = fresh(), wd = fresh(); const w = witnessSigner(1);
    publishCheckpoint({ engine: s.engine, dir: pub });
    const logKey = s.logSigner.did;
    expect(await runWitness({ source: pub, outDir: wd, signer: w, logKey, now: s.clock.now() })).toMatchObject({ status: 'cosigned' });
    expect(await runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() })).toMatchObject({ status: 'unchanged' }); // pin read from the store
    grow(s, 'as-8'); publishCheckpoint({ engine: s.engine, dir: pub });
    grow(s, 'as-9'); publishCheckpoint({ engine: s.engine, dir: pub });
    const r = await runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() });
    expect(r.status).toBe('cosigned'); expect(r.size).toBe(s.engine.log.size());
    const items = readWitnessDir(wd, s.engine.log.logId);
    expect(items.map((i) => i.checkpoint.payload.size)).toEqual([...new Set(items.map((i) => i.checkpoint.payload.size))].sort((a, b) => a - b));
    expect(items).toHaveLength(2);
    expect(JSON.parse(readFileSync(join(wd, 'witness.json'), 'utf8')).witness).toBe(w.did);
  });
  it('a wrong pin, a missing first pin and a forged checkpoint are refused', async () => {
    const s = world(1); const pub = fresh(), wd = fresh(); const w = witnessSigner(1);
    publishCheckpoint({ engine: s.engine, dir: pub });
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w }))).toBe('bad_pin');
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, logKey: s.issuer.did }))).toBe('bad_checkpoint');
    await runWitness({ source: pub, outDir: wd, signer: w, logKey: s.logSigner.did });
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, logKey: s.issuer.did }))).toBe('bad_pin');
  });
  it('detects a fork (same size, other root) and a rollback and writes evidence', async () => {
    const s = world(1); const pub = fresh(), wd = fresh(); const w = witnessSigner(1);
    publishCheckpoint({ engine: s.engine, dir: pub });
    await runWitness({ source: pub, outDir: wd, signer: w, logKey: s.logSigner.did, now: s.clock.now() });
    const latest = join(pub, 'checkpoints', 'latest.json'); const f = JSON.parse(readFileSync(latest, 'utf8'));
    const forgedPayload = { ...f.checkpoint.payload, rootHash: 'e'.repeat(64) };
    const forged = { ...f, checkpoint: { payload: forgedPayload, jws: s.logSigner.sign('sanad-checkpoint+jws', forgedPayload) } };
    writeFileSync(latest, JSON.stringify(forged));
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() }))).toBe('witness_alert');
    expect(readdirSync(join(wd, s.engine.log.logId)).some((x) => x.startsWith('ALERT-'))).toBe(true);
    const smaller = { ...f.checkpoint.payload, size: f.checkpoint.payload.size - 1 };
    writeFileSync(latest, JSON.stringify({ ...f, checkpoint: { payload: smaller, jws: s.logSigner.sign('sanad-checkpoint+jws', smaller) } }));
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() + 1 }))).toBe('witness_alert');
  });
  it('a rewritten history (consistency proof fails) and a broken chain raise an alert', async () => {
    const s = world(1); const pub = fresh(), wd = fresh(); const w = witnessSigner(1);
    publishCheckpoint({ engine: s.engine, dir: pub });
    await runWitness({ source: pub, outDir: wd, signer: w, logKey: s.logSigner.did, now: s.clock.now() });
    grow(s, 'as-8'); publishCheckpoint({ engine: s.engine, dir: pub });
    const latest = join(pub, 'checkpoints', 'latest.json'); const f = JSON.parse(readFileSync(latest, 'utf8'));
    writeFileSync(latest, JSON.stringify({ ...f, consistency: f.consistency.map((h) => (h[0] === '0' ? '1' : '0') + h.slice(1)) }));
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() }))).toBe('witness_alert');
    writeFileSync(latest, JSON.stringify({ ...f, previous: { size: 1, rootHash: 'a'.repeat(64) } }));
    expect(await codeOf(runWitness({ source: pub, outDir: wd, signer: w, now: s.clock.now() + 1 }))).toBe('witness_alert');
  });
  it('an unreachable source is source_unavailable', async () => {
    expect(await codeOf(runWitness({ source: fresh(), outDir: fresh(), signer: witnessSigner(1), logKey: 'did:key:zx' }))).toBe('source_unavailable');
  });
  it('works over HTTP (fetch) from a static server', async () => {
    const s = world(1); const pub = fresh(), wd = fresh();
    publishCheckpoint({ engine: s.engine, dir: pub });
    const { createServer } = await import('node:http');
    const srv = createServer((req, res) => { const f = join(pub, req.url); if (existsSync(f)) { res.writeHead(200); res.end(readFileSync(f)); } else { res.writeHead(404); res.end(); } });
    await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
    const r = await runWitness({ source: 'http://127.0.0.1:' + srv.address().port + '/', outDir: wd, signer: witnessSigner(1), logKey: s.logSigner.did, now: s.clock.now() });
    expect(r.status).toBe('cosigned');
    await new Promise((ok) => srv.close(ok));
  });

  it('verifyWitnesses counts distinct pinned witnesses whose cosigned checkpoint extends the credential\'s', () => {
    const s = world(1); const cred = s.docs[0]; const base = cred.sanad.log.checkpoint; const res = createResolver();
    grow(s, 'as-8');
    const later = s.engine.log.checkpoint(); const c = s.engine.log.consistency(base.payload.size, later.payload.size);
    const cons = [{ m: c.m, n: c.n, rootM: c.rootM, rootN: c.rootN, proof: c.proof }];
    const w1 = witnessSigner(1), w2 = witnessSigner(2), w3 = witnessSigner(3);
    const cosign = (w, cp) => ({ checkpoint: cp, cosignature: makeCosignature({ signer: w, checkpoint: cp, logKey: s.logSigner.did, now: Date.parse('2026-03-02T00:00:00Z') }) });
    const args = (cosigned, trusted = [w1.did, w2.did], consistency = cons) => ({ checkpoint: base, logKey: s.logSigner.did, resolver: res, cosigned, consistency, trusted });
    expect(verifyWitnesses(args([cosign(w1, later), cosign(w2, base)])).count).toBe(2);
    expect(verifyWitnesses(args([cosign(w1, later), cosign(w1, base)])).count).toBe(1);
    expect(verifyWitnesses(args([cosign(w3, later)])).problems.join()).toMatch(/not pinned/);
    expect(verifyWitnesses(args([cosign(w1, later)], undefined, [])).problems.join()).toMatch(/consistency proof/);
    expect(verifyWitnesses(args([cosign(w1, later)], [])).problems.join()).toMatch(/no witness is pinned/);
    const tampered = cosign(w1, later); tampered.cosignature.witnessedAt = '2026-03-03T00:00:00.000Z';
    expect(verifyWitnesses(args([tampered])).problems.join()).toMatch(/signature refused/);
    const wrongLog = { ...cosign(w1, later) }; wrongLog.cosignature = makeCosignature({ signer: w1, checkpoint: later, logKey: s.issuer.did, now: Date.now() });
    expect(verifyWitnesses(args([wrongLog])).count).toBe(0);
    const forkedPayload = { ...base.payload, rootHash: 'd'.repeat(64) }; const forkedCp = { payload: forkedPayload, jws: s.logSigner.sign('sanad-checkpoint+jws', forkedPayload) };
    expect(verifyWitnesses(args([cosign(w1, forkedCp)])).problems.join()).toMatch(/forked/);
  });

  it('verifyCredential and verify-bundle with requireWitnesses', async () => {
    const s = world(1); const pub = fresh(), wd = fresh(), out = fresh(); const w = witnessSigner(1);
    grow(s, 'as-8'); s.clock.advance(1000);
    publishCheckpoint({ engine: s.engine, dir: pub });
    await runWitness({ source: pub, outDir: wd, signer: w, logKey: s.logSigner.did, now: s.clock.now() });
    const b = buildBundleFiles({ engine: s.engine, credentialId: s.docs[0].id, issuerSigner: s.issuer, checkpointsDir: pub, witnessDirs: [wd], now: s.clock.now() });
    writeFiles(out, b.files);
    expect(b.files.has('bundles/' + b.bundleHash + '/witnesses.json')).toBe(true);
    const files = readBundlePath(join(out, 'bundles', b.bundleHash));
    const ok = verifyBundleFiles(files, opts(s, { requireWitnesses: 1, trustedWitnesses: [w.did] }));
    expect(ok.ok, JSON.stringify(ok.checks.filter((c) => !c.ok))).toBe(true);
    expect(ok.checks.find((c) => c.name === 'witnesses').ok).toBe(true);
    expect(failedNames(verifyBundleFiles(files, opts(s, { requireWitnesses: 2, trustedWitnesses: [w.did] })))).toEqual(['witnesses']);
    expect(failedNames(verifyBundleFiles(files, opts(s, { requireWitnesses: 1 })))).toEqual(['witnesses']);
    expect(verifyBundleFiles(files, opts(s)).checks.some((c) => c.name === 'witnesses')).toBe(false);
    // dropping the consistency proofs makes the witness unusable
    const d = 'bundles/' + b.bundleHash + '/'; const m = new Map(files); m.set(d + 'consistency.json', '[]');
    const man = JSON.parse(m.get(d + 'manifest.json')); man.files['consistency.json'] = sha('[]'); m.set(d + 'manifest.json', JSON.stringify(man));
    expect(failedNames(verifyBundleFiles(m, opts(s, { requireWitnesses: 1, trustedWitnesses: [w.did] })))).toEqual(['witnesses']);
  });
});
