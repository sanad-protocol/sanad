// Reproductions of the findings of the independent review (each failed before its fix).
import { describe, it, expect } from 'vitest';
import * as H from './helpers.mjs';
import {
  createEngine, createMemoryStore, makeSigner, keyPairFromSeed, createResolver, verifyCredential, buildCredential, sealBundle, bundleHashOf, createLog,
  commitFor, attestationStatement, core, base58btcEncode, prepareCommit, prepareReveal, createHttpServer, validatePolicy,
} from '../src/index.mjs';
import { createDemoAttestor } from '../src/demo-keys.mjs';

const seed = (n) => new Uint8Array(32).fill(n);
const POL = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8, asOf: '2026-03-02' };
const clone = (v) => JSON.parse(JSON.stringify(v));
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

function honest(over = {}) {
  const s = H.setup(over); H.newAssessment(s.engine);
  const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
  const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 4).secret);
  sec.forEach((x, k) => H.revealAs(s.engine, s.people['AB'[k]], 'as-1', x));
  s.clock.advance(1000);
  return { ...s, doc: s.engine.finalize('as-1') };
}
const pins = (s) => ({ trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did] });

describe('C1: keys are pinned, not DID strings; embedded DID histories are untrusted', () => {
  function forged() {
    const issuer = makeSigner(keyPairFromSeed(seed(51)).privateKey, 'did:web:trusted-university.example');
    const logS = makeSigner(keyPairFromSeed(seed(52)).privateKey, 'did:web:log.trusted-university.example');
    const eng = createEngine({ store: createMemoryStore(), issuer, logSigner: logS, clock: H.makeClock() });
    for (const s of [issuer, logS]) eng.registerDid({ id: s.did, versions: [{ version: 1, validFrom: '2026-01-01', keys: [{ id: '#k1', publicKeyMultibase: 'z' + base58btcEncode(s.publicKey) }], revoked: [] }] });
    eng.registerTemplate(H.template({ attestors: { min: 1, max: 3, roles: ['examiner'] } }));
    const A = createDemoAttestor('A', seed(10));
    H.newAssessment(eng, { claimedLevel: 5 });
    const i = eng.invite('as-1', { attestor: A.did, role: 'examiner', evidence: 'E1' });
    const c = H.commitAs(eng, A, 'as-1', i.attestationId, 5);
    H.revealAs(eng, A, 'as-1', c.secret);
    return { doc: eng.finalize('as-1', { allowShortfall: true }), issuer, logS };
  }
  it('a credential whose issuer is a did:web known only from its own embedded history is not accepted by DID name alone', () => {
    const { doc } = forged();
    const r = verifyCredential(doc, { resolver: createResolver(), trustedIssuers: ['did:web:trusted-university.example'], trustedLogKeys: ['did:web:log.trusted-university.example'], policy: POL });
    expect(r.ok).toBe(false); expect(failed(r)).toContain('did-histories');
    expect(r.warnings.join(' ')).toMatch(/embedded/);
  });
  it('is accepted when the verifier pins the keys, or supplies the histories itself', () => {
    const { doc, issuer, logS } = forged();
    const mb = (s) => 'z' + base58btcEncode(s.publicKey);
    const base = { resolver: createResolver(), trustedIssuers: [issuer.did], trustedLogKeys: [logS.did], policy: POL };
    expect(verifyCredential(doc, { ...base, pinnedKeys: { [issuer.did]: [mb(issuer)], [logS.did]: [mb(logS)] } }).ok).toBe(true);
    expect(verifyCredential(doc, { ...base, trustedDidHistories: doc.sanad.dids }).ok).toBe(true);
    expect(verifyCredential(doc, { ...base, pinnedKeys: { [issuer.did]: ['z' + base58btcEncode(seed(9))] } }).ok).toBe(false);
  });
  it('an attacker who forges the whole chain under a did:web name with its own keys fails against a verifier that pinned the real keys', () => {
    const { doc, issuer, logS } = forged();
    const real = { [issuer.did]: ['z' + base58btcEncode(seed(7))], [logS.did]: ['z' + base58btcEncode(seed(8))] };
    expect(verifyCredential(doc, { resolver: createResolver(), trustedIssuers: [issuer.did], trustedLogKeys: [logS.did], pinnedKeys: real, policy: POL }).ok).toBe(false);
  });
});

describe('H1: the whole policy is validated everywhere', () => {
  it('verifyCredential reports a partial or malformed policy as a failed check, never a result', () => {
    const s = honest();
    for (const p of [{ halfLifeMonths: 24, asOf: '2026-03-02' }, { ...POL, minAttestors: 'x' }, { ...POL, minAgreement: '0.9' }, { ...POL, asOf: 'soon' }]) {
      const r = s.engine.verifyCredential(s.doc, { policy: p });
      expect(r.ok).toBe(false); expect(failed(r)).toContain('policy'); expect(r.recognition).toBeNull();
    }
  });
  it('previewRecognition refuses with bad_policy, and validatePolicy lists every problem', () => {
    const s = honest();
    for (const p of [{ halfLifeMonths: 24 }, { ...POL, minAttestors: -3 }]) H.code(() => s.engine.previewRecognition('as-1', { policy: p }), 'bad_policy');
    expect(validatePolicy(POL)).toEqual([]); expect(validatePolicy({}).length).toBe(8);
  });
});

describe('H3: the verifier decides its own policy, date and pins', () => {
  it('without a policy there is no recognition and ok is false; useRecommendedPolicy is an explicit opt-in that is labelled', () => {
    const s = honest();
    const r = s.engine.verifyCredential(s.doc);
    expect(r.ok).toBe(false); expect(failed(r)).toContain('policy'); expect(r.recognition).toBeNull();
    const o = s.engine.verifyCredential(s.doc, { useRecommendedPolicy: true });
    expect(o.ok).toBe(true); expect(o.basis).toMatchObject({ policySource: 'issuer-recommendation', asOfSource: 'credential-date' });
  });
  it('asOf is required: a policy without asOf and no asOf option fails; useVerifierClock uses the supplied clock', () => {
    const s = honest(); const { asOf: _a, ...noAsOf } = POL;
    expect(s.engine.verifyCredential(s.doc, { policy: noAsOf }).ok).toBe(false);
    const c = s.engine.verifyCredential(s.doc, { policy: noAsOf, useVerifierClock: true, now: Date.parse('2026-03-02T00:00:00Z') });
    expect(c.ok).toBe(true); expect(c.recognition.policy.asOf).toBe('2026-03-02'); expect(c.basis.asOfSource).toBe('verifier-clock');
    expect(s.engine.verifyCredential(s.doc, { policy: noAsOf, asOf: '2026-03-02' }).ok).toBe(true);
  });
  it('an unpinned issuer or log key makes ok false unless allowUnpinned is set (then it is a warning)', () => {
    const s = honest();
    const r = verifyCredential(s.doc, { policy: POL });
    expect(r.ok).toBe(false); expect(failed(r)).toEqual(expect.arrayContaining(['trusted-issuer', 'trusted-log-key']));
    const a = verifyCredential(s.doc, { policy: POL, allowUnpinned: true });
    expect(a.ok).toBe(true); expect(a.warnings.join(' ')).toMatch(/not pinned/);
    expect(verifyCredential(s.doc, { policy: POL, ...pins(s) }).ok).toBe(true);
  });
  it('trustedLogIds pins the log id', () => {
    const s = honest();
    expect(verifyCredential(s.doc, { policy: POL, ...pins(s), trustedLogIds: ['sanad-log'] }).ok).toBe(true);
    const r = verifyCredential(s.doc, { policy: POL, ...pins(s), trustedLogIds: ['another-log'] });
    expect(r.ok).toBe(false); expect(failed(r)).toContain('log');
  });
  it('the report carries the experimental notice', () => {
    const s = honest();
    expect(verifyCredential(s.doc, { policy: POL, ...pins(s) }).notice).toMatch(/experimental.*not (been )?cryptographically reviewed/i);
  });
});

describe('H2: issuer-supplied statistics and the verifier allow-list', () => {
  it('a threshold on issuer-supplied statistics fails by default, passes with allowIssuerStatistics, and verifier statistics replace them', () => {
    const s = honest(); const strict = { ...POL, minAttestorSittings: 3, minAgreement: 0.6 };
    const r = verifyCredential(s.doc, { policy: strict, ...pins(s) });
    expect(r.ok).toBe(false); expect(failed(r)).toContain('attestor-statistics');
    expect(verifyCredential(s.doc, { policy: strict, ...pins(s), allowIssuerStatistics: true }).warnings.join(' ')).toMatch(/issuer-supplied statistics/);
    const mine = Object.fromEntries(Object.keys(s.doc.sanad.bundle.attestors).map((d) => [d, { sittings: 9, agreement: 0.9 }]));
    const v = verifyCredential(s.doc, { policy: strict, ...pins(s), attestorStats: mine });
    expect(v.ok).toBe(true); expect(v.recognition.status).toBe('recognised');
  });
  it('allowedAttestors drops everyone else', () => {
    const s = honest();
    const v = verifyCredential(s.doc, { policy: POL, ...pins(s), allowedAttestors: [s.people.A.did] });
    expect(v.recognition.dropped.some((d) => /allow-list/.test(d.reason))).toBe(true);
    expect(v.recognition.status).not.toBe('recognised');
  });
});

describe('H4: duplicate marks, id prefixes and roles', () => {
  const X = createDemoAttestor('X', seed(20)), Y = createDemoAttestor('Y', seed(21));
  const op = makeSigner(keyPairFromSeed(seed(1)).privateKey), lg = makeSigner(keyPairFromSeed(seed(2)).privateKey);
  function build({ stmts, role = 'examiner', assessment = 'A', template = { id: 't', hash: '0'.repeat(64) } }) {
    const store = createMemoryStore(); const log = createLog({ store, logId: 'L', signer: lg, clock: { now: () => Date.parse('2026-03-01T10:00:00Z') } });
    const atts = stmts.map(([p, id, level]) => { const nonce = 'N'.repeat(22) + id.replace(/\W/g, ''); const st = attestationStatement({ id, attestor: p.did, evidence: 'A.E1', level, role, conflictDeclared: false, date: '2026-03-01', commit: commitFor({ attestor: p.did, evidence: 'A.E1', level, nonce }), nonce }); return { statement: st, signature: p.signer.sign('sanad-attestation+jws', st) }; });
    const ev = core.sealEvidence({ id: 'A.E1', kind: 'sitting', date: '2026-03-01', summary: 's', body: { kind: 'sitting', date: '2026-03-01' } });
    const bundle = sealBundle({ skill: 's', claimedLevel: 5, subject: 'urn:uuid:s', evidence: [ev], attestations: atts, attestors: {} });
    const idx = bundle.attestations.map((a) => log.append({ kind: 'attestation', ref: a.hash }).index); idx.push(log.append({ kind: 'bundle', ref: bundleHashOf(bundle) }).index);
    const cp = log.checkpoint();
    const embedded = { logId: 'L', logKey: lg.did, entries: idx.map((i) => ({ index: i, leaf: log.entries(i, i + 1)[0].leaf })), proofs: idx.map((i) => ({ index: i, size: cp.payload.size, proof: log.inclusion(i, cp.payload.size).proof })), checkpoint: cp };
    return buildCredential({ bundle, issuer: op, template, assessment, process: { invited: 2, committed: 2, revealed: 2, missing: [], late: [], notCommitted: [] }, policy: { id: 'p', minAttestors: 1, requireLive: false, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8 }, log: embedded, dids: [], now: Date.parse('2026-03-01T10:00:00Z') });
  }
  const pn = { trustedIssuers: [op.did], trustedLogKeys: [lg.did], policy: POL };
  it('one attestor signing twice on one evidence item counts once', () => {
    const r = verifyCredential(build({ stmts: [[X, 'A.a01', 5], [X, 'A.a02', 5], [Y, 'A.a03', 1]] }), pn);
    expect(r.recognition.dropped.map((d) => d.id)).toContain('A.a02');
    expect(r.recognition.used.attestations).toEqual(['A.a01', 'A.a03']);
  });
  it('attestation ids must belong to the credential\'s assessment', () => {
    const r = verifyCredential(build({ stmts: [[X, 'ZZZ.a01', 5], [Y, 'QQQ.a07', 5]] }), pn);
    expect(r.ok).toBe(false); expect(failed(r)).toContain('ids');
  });
  it('a verifier that supplies the template gets the template hash and the roles checked', () => {
    const t = H.template();
    const good = verifyCredential(build({ stmts: [[X, 'A.a01', 4], [Y, 'A.a02', 4]], template: { id: t.id, hash: core.hashOf(t) } }), { ...pn, template: t });
    expect(good.checks.find((c) => c.name === 'template')?.ok).toBe(true);
    const wrongRole = verifyCredential(build({ role: 'peer', stmts: [[X, 'A.a01', 4], [Y, 'A.a02', 4]], template: { id: t.id, hash: core.hashOf(t) } }), { ...pn, template: t });
    expect(wrongRole.ok).toBe(false); expect(failed(wrongRole)).toContain('template');
    expect(failed(verifyCredential(build({ stmts: [[X, 'A.a01', 4], [Y, 'A.a02', 4]] }), { ...pn, template: t }))).toContain('template'); // hash differs
  });
});

describe('M2: the phases are monotonic and a clock that steps back changes nothing', () => {
  const two = () => { const s = H.setup(); H.newAssessment(s.engine); const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' })); return { ...s, inv }; };
  it('a commit is refused once any reveal exists, even if the clock goes back', () => {
    const s = two();
    const a = H.commitAs(s.engine, s.people.A, 'as-1', s.inv[0].attestationId, 5).secret;
    s.clock.advance(25 * H.HOUR);
    H.revealAs(s.engine, s.people.A, 'as-1', a, '2026-03-02');
    s.clock.advance(-2 * H.HOUR);
    H.code(() => H.commitAs(s.engine, s.people.B, 'as-1', s.inv[1].attestationId, 5), 'commit_closed');
  });
  it('the engine clock never runs backwards: deadlines already passed stay passed', () => {
    const s = two();
    s.clock.advance(25 * H.HOUR);
    H.code(() => H.commitAs(s.engine, s.people.A, 'as-1', s.inv[0].attestationId, 3), 'commit_closed');
    s.clock.advance(-5 * H.HOUR);
    H.code(() => H.commitAs(s.engine, s.people.A, 'as-1', s.inv[0].attestationId, 3), 'commit_closed');
    expect(Date.parse(s.engine.info().time)).toBeGreaterThanOrEqual(Date.parse('2026-03-02T10:00:00Z'));
  });
});

describe('enforcement at finalize (template minimum and live sitting)', () => {
  it('a single attestor cannot finalize a min:2 template unless the operator says so, and the shortfall is recorded', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const c = H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 4).secret; H.revealAs(s.engine, s.people.A, 'as-1', c);
    H.code(() => s.engine.finalize('as-1'), 'below_template_minimum');
    const doc = s.engine.finalize('as-1', { allowShortfall: true });
    expect(doc.sanad.process.shortfall).toEqual([expect.stringMatching(/as-1\.E1.*1.*2/)]);
    expect(verifyCredential(doc, { policy: POL, trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did] }).checks[0].ok).toBe(true);
  });
});

describe('lows', () => {
  it('stats route does not answer for object prototype names', () => {
    const { engine } = H.setup();
    for (const k of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) expect(engine.stats(k)).toEqual({ sittings: 0, agreement: 0 });
  });
  it('a late reveal is recorded only when its signature is valid', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 3).secret);
    s.clock.advance(80 * H.HOUR);
    const good = prepareReveal({ signer: s.people.A.signer, assessment: s.engine.getAssessment('as-1'), attestationId: inv[0].attestationId, secret: sec[0], date: '2026-03-04' });
    const forged = { ...good, jws: s.people.B.signer.sign('sanad-attestation+jws', good.statement) };
    H.code(() => s.engine.reveal('as-1', forged), 'bad_signature');
    expect(s.engine.getAssessment('as-1').late).toEqual([]);
    H.code(() => s.engine.reveal('as-1', { attestationId: inv[0].attestationId, statement: { junk: 1 }, jws: 'x' }), 'bad_statement');
    expect(s.engine.getAssessment('as-1').late).toEqual([]);
    H.code(() => s.engine.reveal('as-1', good), 'reveal_late');
    expect(s.engine.getAssessment('as-1').late).toEqual([inv[0].attestationId]);
  });
  it('subjects in personal namespaces are refused, and a subject DID can be excluded as attestor', () => {
    const { engine, people: P } = H.setup();
    for (const subject of ['urn:email:ada@example.org', 'urn:person:ada', 'urn:name:ada', 'urn:tel:+4930123', 'urn:phone:123', 'urn:uuid:ada@example.org', 'URN:Email:x']) H.code(() => H.newAssessment(engine, { subject }), 'bad_subject');
    H.newAssessment(engine, { subjectDid: P.A.did });
    H.code(() => engine.invite('as-1', { attestor: P.A.did, role: 'examiner', evidence: 'E1' }), 'subject_as_attestor');
  });
  it('finalize can be retried after a crash without duplicate log leaves or a second credential', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 3).secret);
    sec.forEach((x, k) => H.revealAs(s.engine, s.people['AB'[k]], 'as-1', x));
    // simulate a crash after the log leaves were written but before the assessment was saved
    const realPut = s.store.put.bind(s.store); let boom = true;
    s.store.put = (c, id, v) => { if (boom && c === 'assessments' && v.state === 'finalized') { boom = false; throw new Error('disk full'); } return realPut(c, id, v); };
    expect(() => s.engine.finalize('as-1')).toThrow(/disk full/);
    const sizeAfterCrash = s.engine.log.size();
    const doc = s.engine.finalize('as-1');
    expect(s.engine.log.size()).toBe(sizeAfterCrash); // no duplicate leaves
    expect(s.store.list('credentials')).toHaveLength(1);
    expect(verifyCredential(doc, { policy: POL, trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did], asOf: '2026-03-01' }).ok).toBe(true);
  });
});

describe('HTTP hardening (M4 and I-JSON)', () => {
  const TOKEN = 'operator-token-0123456789';
  async function withServer(fn) {
    const ctx = H.setup(); const server = createHttpServer({ engine: ctx.engine, operatorToken: TOKEN });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    const base = 'http://127.0.0.1:' + server.address().port;
    const post = async (p, body, auth = true) => { const r = await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: 'Bearer ' + TOKEN } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };
    try { await fn({ ctx, post, base }); } finally { await new Promise((ok) => server.close(ok)); }
  }
  it('rejects lone surrogates, unsafe integers, non-finite numbers and deep nesting with a clean 400', async () => {
    await withServer(async ({ post }) => {
      const base = '{"templateId":"maths-oral-v1","subject":"urn:uuid:1","claimedLevel":3,"id":"p1","evidence":[{"key":"E1","date":"2026-03-01","summary":"s","body":';
      await post('/v1/templates', H.template());
      for (const [name, body] of [['surrogate', '{"x":"\\ud800"}'], ['bigint', '{"n":9007199254740993}'], ['infinity', '{"n":1e400}'], ['deep', '{"a":' + '['.repeat(5000) + ']'.repeat(5000) + '}']]) {
        const r = await post('/v1/assessments', base + body + '}]}');
        expect(r.status, name).toBe(400); expect(r.json.error, name).toMatch(/bad_json|bad_number|too_deep|bad_string/);
      }
      expect((await post('/v1/verify', '{"credential":' + '['.repeat(100000) + ']'.repeat(100000) + '}', false)).status).toBe(400);
    });
  });
  it('caps what /v1/verify will process', async () => {
    await withServer(async ({ post }) => {
      const doc = { credential: { sanad: { bundle: { attestations: new Array(5000).fill({}), evidence: [] } } } };
      const r = await post('/v1/verify', doc, false);
      expect(r.status).toBe(400); expect(r.json.error).toBe('too_large');
    });
  });
  it('verify over HTTP requires an explicit policy', async () => {
    await withServer(async ({ ctx, post }) => {
      const s = honest();
      const r = await post('/v1/verify', { credential: s.doc }, false);
      expect(r.status).toBe(200); expect(r.json.ok).toBe(false); expect(r.json.checks.find((c) => c.name === 'policy').ok).toBe(false);
      void ctx;
    });
  });
  it('errors never put a stack trace in the logs', async () => {
    const lines = [];
    const ctx = H.setup(); const server = createHttpServer({ engine: { ...ctx.engine, info() { throw new Error('boom'); } }, operatorToken: TOKEN, onError: (m) => lines.push(m) });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    const r = await fetch('http://127.0.0.1:' + server.address().port + '/v1/info');
    await new Promise((ok) => server.close(ok));
    expect(r.status).toBe(500); expect(lines.join('\n')).not.toMatch(/\n\s+at /);
  });
});

describe('browser helper', () => {
  it('makes a non-extractable private key', async () => {
    const { newAttestor } = await import('../static/sanad-client.js');
    const a = await newAttestor();
    expect(a.privateKeyExtractable).toBe(false);
  });
});
