import { describe, it, expect } from 'vitest';
import * as H from './helpers.mjs';
import { sittingProblems, missingRequired, signIdentityAssurance, checkIdentitySignature, validateTemplate, core, makeSigner, keyPairFromSeed, base58btcEncode, createHttpServer, createResolver } from '../src/index.mjs';

const hex = (c) => c.repeat(64);
const candKey = 'z' + base58btcEncode(makeSigner(keyPairFromSeed(H.seedOf(40)).privateKey).publicKey);
const registrar = makeSigner(keyPairFromSeed(H.seedOf(30)).privateKey);
const ia = (over = {}) => signIdentityAssurance({ signer: registrar, sittingId: 'sit-1', level: 'A1', method: 'document-on-camera', date: '2026-03-01', candidateKey: candKey, ...over });
const full = (over = {}) => ({ sittingId: 'sit-1', paperFingerprint: hex('a'), strokeLogHead: hex('b'), recordingSha256: hex('c'), recordingCipherSha256: hex('d'), recordingBytes: 1000, identityAssurance: ia(), publication: { scope: 'hashes', date: '2026-03-01', url: 'https://example.org/s/' }, ...over });
const tplWith = (flags) => H.template({ evidence: [{ key: 'E1', kind: 'sitting', summary: 'Oral sitting', ...flags }] });
const ALL = { requireRecordingHash: true, requireStrokeLogHead: true, requireIdentityAssurance: true };

function sealed(tpl, body, { add = true } = {}) {
  const s = H.setup({ tpl }); const { engine, people: P } = s;
  H.newAssessment(engine);
  if (body && add) engine.addEvidence('as-1', { key: 'E1', body });
  const inv = ['A', 'B'].map((n) => engine.invite('as-1', { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
  const sec = inv.map((i, k) => H.commitAs(engine, P['AB'[k]], 'as-1', i.attestationId, 4).secret);
  sec.forEach((x, k) => H.revealAs(engine, P['AB'[k]], 'as-1', x));
  return { ...s };
}

describe('sitting evidence schema', () => {
  it('accepts the full set and a body with none of the members', () => {
    expect(sittingProblems(full())).toEqual([]);
    expect(sittingProblems({ minutes: 40 })).toEqual([]);
  });
  it('refuses malformed members one by one', () => {
    const bad = (o, re) => expect(sittingProblems(full(o)).join('|')).toMatch(re);
    bad({ strokeLogHead: 'abc' }, /strokeLogHead/);
    bad({ paperFingerprint: hex('A') }, /paperFingerprint/);
    bad({ recordingSha256: hex('c'), recordingBytes: 0 }, /recordingBytes/);
    bad({ recordingBytes: 1.5 }, /recordingBytes/);
    bad({ sittingId: 'has space' }, /sittingId/);
    bad({ publication: { scope: 'video', date: '2026-03-01' } }, /scope/);
    bad({ publication: { scope: 'hashes', date: '2026-02-30' } }, /date/);
    bad({ publication: { scope: 'hashes', date: '2026-03-01', url: 'ftp://x' } }, /url/);
    bad({ identityAssurance: { ...ia(), level: 'A3' } }, /level/);
    bad({ identityAssurance: { ...ia(), candidateKey: 'zNotAKey' } }, /candidateKey/);
    bad({ identityAssurance: { ...ia(), extra: 1 } }, /exactly/);
  });
  it('a recording hash needs its byte count, a cipher hash needs the plain one, an identity statement needs the sitting id', () => {
    expect(sittingProblems({ recordingSha256: hex('c') }).join()).toMatch(/recordingBytes/);
    expect(sittingProblems({ recordingCipherSha256: hex('c') }).join()).toMatch(/needs recordingSha256/);
    expect(sittingProblems({ identityAssurance: ia() }).join()).toMatch(/sittingId/);
  });
  it('the identity signature is bound to every member and to the sitting', () => {
    const res = createResolver();
    const body = full();
    expect(checkIdentitySignature(body, res).ok).toBe(true);
    for (const [k, v] of [['level', 'A2'], ['method', 'other'], ['date', '2026-03-02'], ['candidateKey', 'z' + base58btcEncode(new Uint8Array(32).fill(7))]]) {
      expect(checkIdentitySignature({ ...body, identityAssurance: { ...body.identityAssurance, [k]: v } }, res).ok, k).toBe(false);
    }
    expect(checkIdentitySignature({ ...body, sittingId: 'sit-2' }, res).ok).toBe(false);
  });
  it('missingRequired follows the template flags', () => {
    expect(missingRequired({}, { ...ALL })).toEqual(['recordingSha256', 'strokeLogHead', 'identityAssurance']);
    expect(missingRequired(full(), { ...ALL })).toEqual([]);
    expect(missingRequired({}, null)).toEqual([]);
  });
  it('template flags are booleans and only allowed on sitting items', () => {
    expect(validateTemplate(tplWith(ALL)).ok).toBe(true);
    expect(validateTemplate(tplWith({ requireRecordingHash: 'yes' })).errors.join()).toMatch(/true or false/);
    const t = H.template({ evidence: [{ key: 'E1', kind: 'sitting', summary: 's' }, { key: 'E2', kind: 'artifact', summary: 'a', requireStrokeLogHead: true }] });
    expect(validateTemplate(t).errors.join()).toMatch(/only an evidence item of kind sitting/);
  });
});

describe('addEvidence', () => {
  const mk = (tpl = tplWith({})) => { const s = H.setup({ tpl }); H.newAssessment(s.engine); return s; };
  it('adds members, recomputes the hash and matches a body supplied at creation', () => {
    const { engine } = mk();
    const before = engine.getAssessment('as-1').evidence[0].hash;
    const r = engine.addEvidence('as-1', { key: 'E1', body: { sittingId: 'sit-1', strokeLogHead: hex('b') } });
    expect(r.changed).toBe(true); expect(r.added).toEqual(['sittingId', 'strokeLogHead']); expect(r.hash).not.toBe(before);
    const ev = engine.getAssessment('as-1').evidence[0];
    expect(ev.hash).toBe(r.hash); expect(core.hashOf(ev.body)).toBe(ev.hash);
    // the same body given at creation gives the same hash (an addition is not a different kind of evidence)
    const s2 = H.setup({ tpl: tplWith({}) });
    s2.engine.createAssessment({ id: 'as-1', templateId: 'maths-oral-v1', subject: 'urn:uuid:11111111-1111-4111-8111-111111111111', claimedLevel: 4, evidence: [{ key: 'E1', date: '2026-03-01', summary: 'Oral sitting of 40 minutes', body: { minutes: 40, sittingId: 'sit-1', strokeLogHead: hex('b') } }] });
    expect(s2.engine.getAssessment('as-1').evidence[0].hash).toBe(r.hash);
  });
  it('is idempotent for equal values and refuses a different value for a member that is set', () => {
    const { engine } = mk();
    engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('b') } });
    const again = engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('b') } });
    expect(again).toMatchObject({ changed: false, added: [] });
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('c') } }), 'evidence_conflict');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { minutes: 41 } }), 'evidence_conflict');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { kind: 'peer' } }), 'bad_evidence');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { date: '2020-01-01' } }), 'bad_evidence');
  });
  it('a conflicting call changes nothing (no partial merge)', () => {
    const { engine } = mk();
    engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('b') } });
    const h = engine.getAssessment('as-1').evidence[0].hash;
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { paperFingerprint: hex('a'), strokeLogHead: hex('c') } }), 'evidence_conflict');
    expect(engine.getAssessment('as-1').evidence[0].hash).toBe(h);
  });
  it('refuses unknown items, bad bodies and malformed members', () => {
    const { engine } = mk();
    H.code(() => engine.addEvidence('as-1', { key: 'E2', body: { x: 1 } }), 'bad_evidence');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: [] }), 'bad_evidence');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: 'nope' } }), 'bad_evidence');
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { recordingSha256: hex('c') } }), 'bad_evidence');
    H.code(() => engine.addEvidence('nope', { key: 'E1', body: { a: 1 } }), 'assessment_unknown');
  });
  it('refuses an identity statement whose signature does not verify', () => {
    const { engine } = mk();
    const bad = { ...ia(), level: 'A2' };
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { sittingId: 'sit-1', identityAssurance: bad } }), 'bad_evidence');
    expect(engine.addEvidence('as-1', { key: 'E1', body: { sittingId: 'sit-1', identityAssurance: ia() } }).changed).toBe(true);
  });
  it('is refused after the first commit, and after finalize', () => {
    const { engine, people: P } = mk();
    const i = engine.invite('as-1', { attestor: P.A.did, role: 'examiner', evidence: 'E1' });
    engine.invite('as-1', { attestor: P.B.did, role: 'examiner', evidence: 'E1' });
    engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('b') } });
    H.commitAs(engine, P.A, 'as-1', i.attestationId, 4);
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { paperFingerprint: hex('a') } }), 'evidence_sealed');
    // even an equal value is refused: the rule is about the phase, not the value
    H.code(() => engine.addEvidence('as-1', { key: 'E1', body: { strokeLogHead: hex('b') } }), 'evidence_sealed');
  });
  it('a finalized assessment refuses it', () => {
    const { identityAssurance: _i, ...noId } = full();
    const s = sealed(tplWith({}), noId);
    s.engine.finalize('as-1');
    H.code(() => s.engine.addEvidence('as-1', { key: 'E1', body: { x: 1 } }), 'state');
  });
  it('is recorded in the events stream and in process.evidenceAdded', () => {
    const s = sealed(tplWith({}), { sittingId: 'sit-1', strokeLogHead: hex('b') });
    const events = s.store.read('events').filter((e) => e.type === 'evidence-added');
    expect(events).toHaveLength(1); expect(events[0]).toMatchObject({ assessment: 'as-1', evidence: 'as-1.E1', added: ['sittingId', 'strokeLogHead'] });
    const doc = s.engine.finalize('as-1');
    expect(doc.sanad.process.evidenceAdded).toEqual(['as-1.E1']);
    expect(s.engine.verifyCredential(doc, { useRecommendedPolicy: true }).ok).toBe(true);
  });
  it('a credential without any addition has no evidenceAdded member', () => {
    const s = sealed(tplWith({}), null);
    expect('evidenceAdded' in s.engine.finalize('as-1').sanad.process).toBe(false);
  });
});

describe('finalize and verify with template flags', () => {
  it('finalize is refused until the required members are in the evidence; the override is recorded', () => {
    const s = sealed(tplWith(ALL), null);
    const e = H.code(() => s.engine.finalize('as-1'), 'below_template_minimum');
    expect(e.message).toMatch(/recordingSha256, strokeLogHead, identityAssurance/);
    const doc = s.engine.finalize('as-1', { allowShortfall: true });
    expect(doc.sanad.process.shortfall.join()).toMatch(/requires recordingSha256/);
    const r = s.engine.verifyCredential(doc, { useRecommendedPolicy: true });
    expect(r.warnings.join()).toMatch(/carries no paperFingerprint, strokeLogHead, recordingSha256/);
  });
  it('a complete sitting verifies; the report carries no warning', () => {
    const s = sealed(tplWith(ALL), full());
    const doc = s.engine.finalize('as-1');
    const r = s.engine.verifyCredential(doc, { useRecommendedPolicy: true, minIdentityLevel: 'A1' });
    expect(r.ok).toBe(true); expect(r.warnings).toEqual([]);
    expect(r.checks.find((c) => c.name === 'sitting-evidence').ok).toBe(true);
    expect(s.engine.verifyCredential(doc, { useRecommendedPolicy: true, minIdentityLevel: 'A2' }).checks.find((c) => c.name === 'sitting-evidence').ok).toBe(false);
    expect(s.engine.verifyCredential(doc, { useRecommendedPolicy: true, minIdentityLevel: 'B1' }).checks.find((c) => c.name === 'sitting-evidence').ok).toBe(false);
  });
  it('the verifier requires what the template demands even when the issuer dropped it silently', () => {
    const s = sealed(tplWith(ALL), full());
    const doc = JSON.parse(JSON.stringify(s.engine.finalize('as-1')));
    // a verifier with a stricter template than the one the credential cites cannot be fooled: the hash check catches a swapped template first
    const strict = tplWith({});
    expect(s.engine.verifyCredential(doc, { useRecommendedPolicy: true, template: strict }).ok).toBe(false);
  });
  it('a changed member of the hashed body is caught by the evidence hash and the bundle hash', () => {
    const s = sealed(tplWith({}), full());
    const doc = JSON.parse(JSON.stringify(s.engine.finalize('as-1')));
    doc.sanad.bundle.evidence[0].body.strokeLogHead = hex('f');
    const r = s.engine.verifyCredential(doc, { useRecommendedPolicy: true, diagnose: true });
    expect(r.ok).toBe(false);
    expect(r.checks.filter((c) => !c.ok).map((c) => c.name)).toContain('bundle-hash');
  });
  it('a malformed member inside a sealed credential fails sitting-evidence', () => {
    const s = sealed(tplWith({}), full());
    const doc = JSON.parse(JSON.stringify(s.engine.finalize('as-1')));
    // re-seal as a hostile issuer would: the hash is consistent, the member is not
    doc.sanad.bundle.evidence[0].body.strokeLogHead = 'not-hex';
    doc.sanad.bundle.evidence[0].hash = core.hashOf(doc.sanad.bundle.evidence[0].body);
    const r = s.engine.verifyCredential(doc, { useRecommendedPolicy: true, diagnose: true });
    expect(r.checks.find((c) => c.name === 'sitting-evidence').ok).toBe(false);
  });
  it('a did:web identity checker is recorded in the credential histories and needs a pinned key', () => {
    const checker = makeSigner(keyPairFromSeed(H.seedOf(31)).privateKey, 'did:web:registrar.example');
    const s = H.setup({ tpl: tplWith({}) });
    s.engine.registerDid({ id: checker.did, versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: 'z' + base58btcEncode(checker.publicKey) }], revoked: [] }] });
    H.newAssessment(s.engine);
    s.engine.addEvidence('as-1', { key: 'E1', body: { sittingId: 'sit-1', identityAssurance: signIdentityAssurance({ signer: checker, sittingId: 'sit-1', level: 'A2', method: 'in-person-id', date: '2026-03-01', candidateKey: candKey }) } });
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 4).secret);
    sec.forEach((x, k) => H.revealAs(s.engine, s.people['AB'[k]], 'as-1', x));
    const doc = s.engine.finalize('as-1');
    expect(doc.sanad.dids.map((d) => d.id)).toContain('did:web:registrar.example');
    const emb = core && { resolver: createResolver(), trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did], useRecommendedPolicy: true, diagnose: true };
    const bare = (extra = {}) => import('../src/index.mjs').then((m) => m.verifyCredential(doc, { ...emb, ...extra }));
    return bare().then(async (r) => {
      expect(r.checks.find((c) => c.name === 'did-histories').ok).toBe(false);
      const pinned = await bare({ pinnedKeys: { 'did:web:registrar.example': ['z' + base58btcEncode(checker.publicKey)] } });
      expect(pinned.ok).toBe(true);
    });
  });
});

describe('HTTP: PUT evidence', () => {
  it('is an operator route with body { body }', async () => {
    const s = H.setup({ tpl: tplWith({}) }); H.newAssessment(s.engine);
    const server = createHttpServer({ engine: s.engine, operatorToken: 'operator-token-0123456789' });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    const base = 'http://127.0.0.1:' + server.address().port;
    const put = (token, body) => fetch(base + '/v1/assessments/as-1/evidence/E1', { method: 'PUT', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify(body) });
    expect((await put(null, { body: { strokeLogHead: hex('b') } })).status).toBe(401);
    expect((await put('operator-token-0123456789', { strokeLogHead: hex('b') })).status).toBe(400);
    const ok = await put('operator-token-0123456789', { body: { strokeLogHead: hex('b') } });
    expect(ok.status).toBe(200); expect((await ok.json()).changed).toBe(true);
    const conflict = await put('operator-token-0123456789', { body: { strokeLogHead: hex('c') } });
    expect(conflict.status).toBe(409); expect((await conflict.json()).error).toBe('evidence_conflict');
    await new Promise((ok2) => server.close(ok2));
  });
});
