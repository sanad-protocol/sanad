// One contract suite, run on every provider of examples/host-port.mjs. What a host relies on is exactly what is checked here:
// response shapes, error codes and statuses. A new provider (another transport, another implementation) is faithful if it passes.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as H from './helpers.mjs';
import { createHttpServer, prepareCommit, prepareReveal, verifyCredential } from '../src/index.mjs';
import { createProvider, PORT_METHODS } from '../examples/host-port.mjs';

const TOKEN = 'operator-token-0123456789';
const MAP = { g1: 0, g2: 1, g3: 2, g4: 3, g5: 4, g6: 5 };
const rejects = async (p, code) => { try { await p; } catch (e) { expect(e.code).toBe(code); expect(typeof e.status).toBe('number'); return e; } throw new Error('expected ' + code); };

function contract(name, make) {
  describe('provider contract: ' + name, () => {
    let ctx, port, close;
    beforeAll(async () => { ctx = H.setup({ tpl: H.template({ levelMap: MAP }) }); ({ port, close } = await make(ctx)); });
    afterAll(async () => { await close?.(); });

    it('offers exactly the port methods', () => { for (const m of PORT_METHODS) expect(typeof port[m], m).toBe('function'); });
    it('info carries the provider time', async () => { const i = await port.info(); expect(i.alg).toBe('sanad-0.1'); expect(i.time).toBe(i.time.slice(0, 10) + 'T' + i.time.slice(11)); expect(i.today).toBe(i.time.slice(0, 10)); });
    it('registering the same template twice returns the same { id, hash }', async () => {
      const a = await port.registerTemplate(H.template({ levelMap: MAP })), b = await port.registerTemplate(H.template({ levelMap: MAP }));
      expect(a).toEqual(b); expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
      await rejects(port.registerTemplate(H.template({ levelMap: MAP, title: 'changed' })), 'template_exists');
    });
    it('runs a whole assessment: invite, remove, ticket, commit, preview, reveal, finalize, verify', async () => {
      const { people: P, clock } = ctx;
      const aid = 'as-' + name;
      const created = await port.createAssessment({ id: aid, templateId: 'maths-oral-v1', subject: 'urn:uuid:66666666-6666-4666-8666-666666666666', claimedLevel: 4, evidence: [{ key: 'E1', date: '2026-03-01', summary: 's', body: {} }] });
      expect(created).toMatchObject({ id: aid, state: 'open', revealOpen: false });
      const inv = [];
      for (const n of ['A', 'B', 'C']) inv.push(await port.invite(aid, { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
      expect(inv.map((i) => i.attestationId)).toEqual([aid + '.a01', aid + '.a02', aid + '.a03']);
      expect(await port.uninvite(aid, inv[2].attestationId, 'unavailable')).toEqual({ removed: aid + '.a03', invited: 2 });
      await rejects(port.ticket(aid, inv[2].attestationId), 'not_invited');
      const tk = await Promise.all(inv.slice(0, 2).map((i) => port.ticket(aid, i.attestationId)));
      expect(tk[0]).toMatchObject({ ticketVersion: 1, assessment: aid, levelMap: MAP });
      const c = [prepareCommit({ signer: P.A.signer, ticket: tk[0], native: 'g5' }), prepareCommit({ signer: P.B.signer, ticket: tk[1], level: 3 })];
      expect(await port.commit(aid, c[0].request)).toEqual({ committed: 1, of: 2 });
      await rejects(port.uninvite(aid, inv[0].attestationId), 'already_committed');
      await rejects(port.commit(aid, c[0].request), 'already_committed');
      await rejects(port.reveal(aid, prepareReveal({ signer: P.A.signer, ticket: tk[0], secret: c[0].secret, date: '2026-03-01' })), 'reveal_not_open');
      expect(await port.commit(aid, c[1].request)).toEqual({ committed: 2, of: 2 });
      const info = await port.info();
      expect(await port.reveal(aid, prepareReveal({ signer: P.A.signer, ticket: tk[0], secret: c[0].secret, date: info.today }))).toEqual({ revealed: 1, of: 2 });
      const pv = await port.preview(aid);
      expect(pv).toMatchObject({ preview: true, provisional: true, counts: { revealed: 1, pending: 1 } });
      expect(JSON.stringify(pv)).not.toContain(c[1].secret.nonce);
      await rejects(port.finalize(aid), 'not_ready');
      await port.reveal(aid, prepareReveal({ signer: P.B.signer, ticket: tk[1], secret: c[1].secret, date: info.today }));
      clock.advance(1000);
      const doc = await port.finalize(aid);
      expect(doc.type).toEqual(['VerifiableCredential', 'SanadCredential']); expect(doc.sanad.process.removed).toEqual([aid + '.a03']);
      const report = await port.verify(doc, { useRecommendedPolicy: true });
      expect(report.ok).toBe(true); expect(report.recognition.level).toBe(3);
      // the same credential verifies with no provider at all (verify-only mode)
      expect(verifyCredential(doc, { trustedIssuers: [ctx.issuer.did], trustedLogKeys: [ctx.logSigner.did], useRecommendedPolicy: true }).ok).toBe(true);
      expect((await port.getAssessment(aid)).state).toBe('finalized');
      expect((await port.checkpoint()).payload.size).toBeGreaterThan(4);
      await rejects(port.invite('nope', { attestor: P.A.did, role: 'examiner', evidence: 'E1' }), 'assessment_unknown');
    });
  });
}

contract('embedded', async (ctx) => ({ port: createProvider({ provider: 'embedded', engine: ctx.engine }) }));

let server;
contract('http', async (ctx) => {
  server = createHttpServer({ engine: ctx.engine, operatorToken: TOKEN });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  return { port: createProvider({ provider: 'http', url: 'http://127.0.0.1:' + server.address().port, operatorToken: TOKEN }), close: () => new Promise((ok) => server.close(ok)) };
});

describe('provider choice is configuration', () => {
  it('an unknown provider is refused; an unreachable HTTP provider fails with a stable code; a wrong token is 401', async () => {
    expect(() => createProvider({ provider: 'carrier-pigeon' })).toThrow(/unknown Sanad provider/);
    await rejects(createProvider({ provider: 'http', url: 'http://127.0.0.1:1', operatorToken: TOKEN, timeoutMs: 500 }).info(), 'provider_unreachable');
    const ctx = H.setup(); const s = createHttpServer({ engine: ctx.engine, operatorToken: TOKEN });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try { await rejects(createProvider({ provider: 'http', url: 'http://127.0.0.1:' + s.address().port, operatorToken: 'wrong-token-0123456789' }).registerTemplate(H.template()), 'unauthorized'); }
    finally { await new Promise((ok) => s.close(ok)); }
  });
});
