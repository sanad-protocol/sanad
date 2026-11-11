import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as H from './helpers.mjs';
import { createHttpServer, prepareCommit, prepareReveal, validateTemplate, nativeOfNonce, nonceWithNative, levelFromNative } from '../src/index.mjs';
import * as client from '../static/sanad-client.js';

const MAP = { g1: 0, g2: 1, g3: 2, g4: 3, g5: 4, g6: 5 };
const tplMap = () => H.template({ levelMap: MAP });
const two = (tpl) => {
  const s = H.setup(tpl ? { tpl } : {}); H.newAssessment(s.engine);
  const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
  return { ...s, inv };
};

describe('provider time', () => {
  it('info carries the provider time and day, taken from the engine clock', () => {
    const { engine, clock } = H.setup();
    expect(engine.info().time).toBe('2026-03-01T09:00:00.000Z'); expect(engine.info().today).toBe('2026-03-01');
    clock.advance(H.DAY); expect(engine.info().today).toBe('2026-03-02');
  });
});

describe('signing ticket', () => {
  it('holds what a client needs and no secret; a client can sign from the ticket alone', () => {
    const { engine, people: P, inv, clock } = two(tplMap());
    const t = engine.ticketFor('as-1', inv[0].attestationId);
    expect(t).toMatchObject({ ticketVersion: 1, assessment: 'as-1', attestationId: 'as-1.a01', attestor: P.A.did, role: 'examiner', evidence: 'as-1.E1', templateHash: engine.getAssessment('as-1').templateHash, levels: [0, 1, 2, 3, 4, 5], levelMap: MAP, serverDay: '2026-03-01', revealOpen: false });
    expect(t.rules.date.notBefore).toBe('2026-03-01'); expect(t.rules.nonce.minLength).toBe(22);
    expect(Object.keys(t.commit.members)).toBeDefined();
    const c = prepareCommit({ signer: P.A.signer, ticket: t, level: 4 });
    engine.commit('as-1', c.request);
    const cb = prepareCommit({ signer: P.B.signer, ticket: engine.ticketFor('as-1', inv[1].attestationId), level: 3 });
    engine.commit('as-1', cb.request);
    engine.reveal('as-1', prepareReveal({ signer: P.A.signer, ticket: t, secret: c.secret, date: t.serverDay }));
    engine.reveal('as-1', prepareReveal({ signer: P.B.signer, ticket: engine.ticketFor('as-1', inv[1].attestationId), secret: cb.secret, date: '2026-03-01' }));
    clock.advance(1000);
    expect(engine.verifyCredential(engine.finalize('as-1'), { useRecommendedPolicy: true }).ok).toBe(true);
  });
  it('is refused for an unknown or removed invitation, and the browser helper accepts a ticket too', async () => {
    const { engine, inv } = two();
    H.code(() => engine.ticketFor('as-1', 'as-1.a09'), 'not_invited');
    const me = await client.newAttestor();
    const i = engine.invite('as-1', { attestor: me.did, role: 'examiner', evidence: 'E1' }).attestationId;
    const t = engine.ticketFor('as-1', i);
    const { request } = await client.prepareCommit({ attestor: me, ticket: t, level: 2 });
    expect(engine.commit('as-1', request).committed).toBe(1);
    void inv;
  });
});

describe('levelMap', () => {
  it('has keys of 1 to 16 letters or digits only, values 0..5', () => {
    expect(validateTemplate(tplMap()).ok).toBe(true);
    expect(validateTemplate(H.template({ levelMap: { 'native-1': 0 } })).ok).toBe(false);
    expect(validateTemplate(H.template({ levelMap: { g1: 6 } })).ok).toBe(false);
  });
  it('helpers: native mark inside the nonce, mapping lookup', () => {
    const n = nonceWithNative('g4', 'r'.repeat(22));
    expect(n).toBe('nm-g4-' + 'r'.repeat(22)); expect(nativeOfNonce(n)).toBe('g4'); expect(nativeOfNonce('r'.repeat(22))).toBeNull();
    expect(levelFromNative(MAP, 'g6')).toBe(5);
    expect(() => levelFromNative(MAP, 'zz')).toThrow(); expect(() => levelFromNative(MAP, '__proto__')).toThrow();
  });
  it('a native mark decides the level, stays hidden until the reveal, and is preserved in the attestation nonce', () => {
    const { engine, people: P, inv, clock } = two(tplMap());
    const ca = prepareCommit({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, native: 'g5', levelMap: MAP });
    expect(ca.secret.level).toBe(4);
    engine.commit('as-1', ca.request);
    expect(JSON.stringify(engine.getAssessment('as-1'))).not.toContain('nm-g5'); // blind: nothing about the native mark before the reveal
    const cb = prepareCommit({ signer: P.B.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[1].attestationId, level: 3 });
    engine.commit('as-1', cb.request);
    engine.reveal('as-1', prepareReveal({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, secret: ca.secret, date: '2026-03-01' }));
    engine.reveal('as-1', prepareReveal({ signer: P.B.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[1].attestationId, secret: cb.secret, date: '2026-03-01' }));
    clock.advance(1000);
    const doc = engine.finalize('as-1');
    expect(nativeOfNonce(doc.sanad.bundle.attestations[0].nonce)).toBe('g5');
    expect(engine.verifyCredential(doc, { useRecommendedPolicy: true }).ok).toBe(true);
  });
  it('a nonce whose native mark disagrees with the revealed level, or is not listed, is refused at the reveal', () => {
    for (const [nonce, level, codeWanted] of [[nonceWithNative('g1', 'q'.repeat(22)), 4, 'native_mismatch'], [nonceWithNative('zz', 'q'.repeat(22)), 4, 'native_unknown']]) {
      const { engine, people: P, inv } = two(tplMap());
      const ca = prepareCommit({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, level, nonce });
      engine.commit('as-1', ca.request);
      engine.commit('as-1', prepareCommit({ signer: P.B.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[1].attestationId, level: 3 }).request);
      H.code(() => engine.reveal('as-1', prepareReveal({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, secret: ca.secret, date: '2026-03-01' })), codeWanted);
    }
  });
  it('without a levelMap the nonce is not interpreted', () => {
    const { engine, people: P, inv } = two();
    const ca = prepareCommit({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, level: 4, nonce: nonceWithNative('g1', 'q'.repeat(22)) });
    engine.commit('as-1', ca.request);
    engine.commit('as-1', prepareCommit({ signer: P.B.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[1].attestationId, level: 3 }).request);
    expect(engine.reveal('as-1', prepareReveal({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, secret: ca.secret, date: '2026-03-01' })).revealed).toBe(1);
  });
  it('the browser helper maps a native mark through the ticket levelMap', async () => {
    const { engine } = two(tplMap());
    const me = await client.newAttestor();
    const id = engine.invite('as-1', { attestor: me.did, role: 'examiner', evidence: 'E1' }).attestationId;
    const { secret } = await client.prepareCommit({ attestor: me, ticket: engine.ticketFor('as-1', id), native: 'g6' });
    expect(secret.level).toBe(5); expect(secret.nonce.startsWith('nm-g6-')).toBe(true);
  });
});

describe('recognition preview', () => {
  const upTo = (n) => {
    const s = two(); const { engine, people: P, inv } = s;
    const sec = [H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 4).secret, H.commitAs(engine, P.B, 'as-1', inv[1].attestationId, 1, 'z'.repeat(22)).secret];
    for (let k = 0; k < n; k++) H.revealAs(engine, P['AB'[k]], 'as-1', sec[k]);
    return { ...s, sec };
  };
  it('before any reveal it returns counts only and no mark', () => {
    const { engine, sec } = upTo(0);
    const p = engine.previewRecognition('as-1');
    expect(p).toMatchObject({ preview: true, provisional: true, policySource: 'template-recommendation', counts: { invited: 2, committed: 2, revealed: 0, pending: 2 } });
    expect(JSON.stringify(p)).not.toContain(sec[1].nonce); expect(p.recognition.status).not.toBe('recognised');
  });
  it('after one reveal it uses only that attestation and never the other mark; the assessment is unchanged', () => {
    const { engine, sec } = upTo(1);
    const before = JSON.stringify(engine.getAssessment('as-1', { view: 'operator' }));
    const p = engine.previewRecognition('as-1');
    expect(p.counts).toMatchObject({ revealed: 1, pending: 1 });
    expect(p.recognition.used.attestations).toEqual(['as-1.a01']);
    expect(JSON.stringify(p)).not.toContain(sec[1].nonce);
    expect(JSON.stringify(engine.getAssessment('as-1', { view: 'operator' }))).toBe(before);
  });
  it('honours a verifier-supplied policy and labels it; refuses a bad policy', () => {
    const { engine } = upTo(2);
    const lenient = engine.previewRecognition('as-1', { policy: { minAttestors: 1, requireLive: false, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 } });
    expect(lenient.policySource).toBe('verifier-supplied'); expect(lenient.provisional).toBe(true);
    H.code(() => engine.previewRecognition('as-1', { policy: 5 }), 'bad_policy');
    H.code(() => engine.previewRecognition('as-1', { policy: { minAttestors: -3 } }), 'bad_policy');
    H.code(() => engine.previewRecognition('nope'), 'assessment_unknown');
  });
});

describe('invitation removal', () => {
  it('removes before the first commit, never reuses an attestation id, and logs an event', () => {
    const { engine, store, people: P, inv } = two();
    expect(engine.removeInvitation('as-1', inv[0].attestationId, { reason: 'examiner unavailable' })).toEqual({ removed: 'as-1.a01', invited: 1 });
    const c = engine.invite('as-1', { attestor: P.C.did, role: 'examiner', evidence: 'E1' });
    expect(c.attestationId).toBe('as-1.a03');
    expect(engine.getAssessment('as-1').removed.map((r) => r.attestationId)).toEqual(['as-1.a01']);
    const ev = store.read('events');
    expect(ev).toHaveLength(1); expect(ev[0]).toMatchObject({ type: 'invitation-removed', assessment: 'as-1', attestationId: 'as-1.a01', attestor: P.A.did, reason: 'examiner unavailable' });
    H.code(() => engine.ticketFor('as-1', 'as-1.a01'), 'not_invited');
    H.code(() => H.commitAs(engine, P.A, 'as-1', 'as-1.a01', 2), 'not_invited');
    H.code(() => engine.removeInvitation('as-1', 'as-1.a01'), 'not_invited');
  });
  it('is refused after that attestor has committed, and after finalize', () => {
    const { engine, people: P, inv, clock } = two();
    const a = H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 3).secret;
    H.code(() => engine.removeInvitation('as-1', inv[0].attestationId), 'already_committed');
    const b = H.commitAs(engine, P.B, 'as-1', inv[1].attestationId, 3).secret;
    H.revealAs(engine, P.A, 'as-1', a); H.revealAs(engine, P.B, 'as-1', b); clock.advance(1000);
    engine.finalize('as-1');
    H.code(() => engine.removeInvitation('as-1', inv[0].attestationId), 'state');
  });
  it('opens the reveal phase when everyone left has committed, and the credential lists the removal and still verifies', () => {
    const { engine, people: P, inv, clock } = two();
    const a = H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 3).secret;
    expect(engine.getAssessment('as-1').revealOpen).toBe(false);
    engine.removeInvitation('as-1', inv[1].attestationId);
    expect(engine.getAssessment('as-1').revealOpen).toBe(true);
    H.revealAs(engine, P.A, 'as-1', a); clock.advance(1000);
    H.code(() => engine.finalize('as-1'), 'below_template_minimum');
    const doc = engine.finalize('as-1', { allowShortfall: true });
    expect(doc.sanad.process).toMatchObject({ invited: 1, committed: 1, revealed: 1, removed: ['as-1.a02'], shortfall: [expect.any(String)] });
    expect(engine.verifyCredential(doc, { useRecommendedPolicy: true }).ok).toBe(true);
  });
  it('a credential without removals keeps the six-member process (older credentials still verify)', () => {
    const { engine, people: P, inv, clock } = two();
    const s = inv.map((i, k) => H.commitAs(engine, P['AB'[k]], 'as-1', i.attestationId, 3).secret);
    s.forEach((x, k) => H.revealAs(engine, P['AB'[k]], 'as-1', x)); clock.advance(1000);
    expect(Object.keys(engine.finalize('as-1').sanad.process)).toEqual(['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted']);
  });
});

describe('HTTP: ticket, preview, removal, time', () => {
  let server, base, ctx;
  const TOKEN = 'operator-token-0123456789';
  beforeAll(async () => {
    ctx = H.setup(); server = createHttpServer({ engine: ctx.engine, operatorToken: TOKEN });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok)); base = 'http://127.0.0.1:' + server.address().port;
  });
  afterAll(() => new Promise((ok) => server.close(ok)));
  const call = async (m, p, b, tok) => { const r = await fetch(base + p, { method: m, headers: { ...(b !== undefined ? { 'content-type': 'application/json' } : {}), ...(tok ? { authorization: 'Bearer ' + tok } : {}) }, body: b === undefined ? undefined : JSON.stringify(b) }); return { status: r.status, json: await r.json() }; };
  it('serves all four', async () => {
    H.newAssessment(ctx.engine);
    const i = ctx.engine.invite('as-1', { attestor: ctx.people.A.did, role: 'examiner', evidence: 'E1' });
    expect((await call('GET', '/v1/info')).json.time).toBe('2026-03-01T09:00:00.000Z');
    expect((await call('GET', '/v1/assessments/as-1/ticket/' + i.attestationId)).json.ticketVersion).toBe(1);
    const pv = await call('POST', '/v1/assessments/as-1/preview', {});
    expect(pv.json.provisional).toBe(true);
    expect((await call('POST', '/v1/assessments/as-1/preview', { policy: [] })).status).toBe(400);
    expect((await call('POST', '/v1/assessments/as-1/invitations/as-1.a01/remove', {})).status).toBe(401);
    expect((await call('POST', '/v1/assessments/as-1/invitations/as-1.a01/remove', { reason: 'x' }, TOKEN)).json.removed).toBe('as-1.a01');
    expect((await call('GET', '/v1/assessments/as-1/ticket/as-1.a01')).status).toBe(404);
  });
});
