import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import * as H from './helpers.mjs';
import { createHttpServer, prepareCommit, prepareReveal, BODY_LIMIT, CSP } from '../src/index.mjs';

const TOKEN = 'operator-token-0123456789';
let server, base, ctx;
beforeAll(async () => {
  ctx = H.setup({ tpl: H.template({ id: 'other-tpl' }) });
  server = createHttpServer({ engine: ctx.engine, operatorToken: TOKEN });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  base = 'http://127.0.0.1:' + server.address().port;
});
afterAll(() => new Promise((ok) => server.close(ok)));

const req = async (method, path, body, { token, type = 'application/json', raw } = {}) => {
  const headers = {};
  if (token) headers.authorization = 'Bearer ' + token;
  if (body !== undefined || raw !== undefined) headers['content-type'] = type;
  const r = await fetch(base + path, { method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  return { status: r.status, json, text, headers: r.headers };
};
const op = (m, p, b) => req(m, p, b, { token: TOKEN });

describe('HTTP API: plumbing', () => {
  it('healthz and info are open', async () => {
    expect((await req('GET', '/healthz')).json).toEqual({ ok: true });
    const i = (await req('GET', '/v1/info')).json;
    expect(i.alg).toBe('sanad-0.1'); expect(i.issuer).toBe(ctx.issuer.did);
  });
  it('operator routes refuse a missing, wrong or malformed token; reads stay open', async () => {
    for (const t of [undefined, 'wrong-token-0123456789', '']) {
      const r = await req('POST', '/v1/templates', H.template({ id: 'x1' }), { token: t });
      expect(r.status).toBe(401); expect(r.json.error).toBe('unauthorized');
    }
    expect((await req('GET', '/v1/templates')).status).toBe(200);
    expect((await req('GET', '/v1/assessments')).status).toBe(401);
  });
  it('requires application/json, valid JSON and a bounded body', async () => {
    expect((await req('POST', '/v1/templates', undefined, { token: TOKEN, type: 'text/plain', raw: '{}' })).status).toBe(415);
    expect((await req('POST', '/v1/templates', undefined, { token: TOKEN, raw: '{nope' })).json.error).toBe('bad_json');
    const big = await req('POST', '/v1/templates', undefined, { token: TOKEN, raw: JSON.stringify({ pad: 'x'.repeat(BODY_LIMIT + 10) }) });
    expect(big.status).toBe(413);
  });
  it('unknown routes are 404, wrong methods 405, engine errors carry code and status, internals never leak', async () => {
    expect((await req('GET', '/nope')).status).toBe(404);
    expect((await req('DELETE', '/v1/templates')).status).toBe(405);
    const r = await req('GET', '/v1/templates/does-not-exist');
    expect(r.status).toBe(404); expect(r.json.error).toBe('template_unknown');
    expect((await req('GET', '/v1/assessments/..%2f..%2fetc')).status).toBe(404);
    expect((await req('GET', '/%E0%A4%A')).status).toBe(400);
  });
  it('serves the demonstration page with a strict CSP and no external code', async () => {
    const r = await req('GET', '/');
    expect(r.status).toBe(200); expect(r.headers.get('content-security-policy')).toBe(CSP);
    expect(CSP).toMatch(/default-src 'none'/); expect(CSP).not.toMatch(/unsafe|https?:|\*/);
    expect(r.text).not.toMatch(/(src|href)="https?:/);
    expect((await req('GET', '/app.js')).headers.get('content-type')).toMatch(/javascript/);
  });
});

describe('HTTP API: a whole assessment, attestors sign on their side', () => {
  it('template, assessment, invite, blind commit, reveal, finalize, verify, log', async () => {
    const { people: P, clock } = ctx;
    expect((await op('POST', '/v1/templates', H.template())).json.id).toBe('maths-oral-v1');
    const body = { id: 'as-http', templateId: 'maths-oral-v1', subject: 'urn:uuid:22222222-2222-4222-8222-222222222222', claimedLevel: 4, evidence: [{ key: 'E1', date: '2026-03-01', summary: 's', body: { m: 1 } }] };
    expect((await op('POST', '/v1/assessments', body)).status).toBe(200);
    const a1 = (await op('POST', '/v1/assessments/as-http/invite', { attestor: P.A.did, role: 'examiner', evidence: 'E1' })).json;
    const a2 = (await op('POST', '/v1/assessments/as-http/invite', { attestor: P.B.did, role: 'examiner', evidence: 'E1' })).json;
    const view = async () => (await req('GET', '/v1/assessments/as-http')).json;
    const ca = prepareCommit({ signer: P.A.signer, assessment: await view(), attestationId: a1.attestationId, level: 4 });
    const cb = prepareCommit({ signer: P.B.signer, assessment: await view(), attestationId: a2.attestationId, level: 3 });
    expect((await req('POST', '/v1/assessments/as-http/commit', ca.request)).json.committed).toBe(1);
    // a commit is public but hides the mark: the public view holds no nonce and no level before reveal
    const mid = await view(); expect(JSON.stringify(mid)).not.toContain(ca.secret.nonce);
    expect((await req('POST', '/v1/assessments/as-http/reveal', prepareReveal({ signer: P.A.signer, assessment: mid, attestationId: a1.attestationId, secret: ca.secret, date: '2026-03-01' }))).json.error).toBe('reveal_not_open');
    expect((await req('POST', '/v1/assessments/as-http/commit', cb.request)).json.committed).toBe(2);
    for (const [p, c, i] of [[P.A, ca, a1], [P.B, cb, a2]]) {
      const r = await req('POST', '/v1/assessments/as-http/reveal', prepareReveal({ signer: p.signer, assessment: await view(), attestationId: i.attestationId, secret: c.secret, date: '2026-03-01' }));
      expect(r.status).toBe(200);
    }
    clock.advance(1000);
    expect((await op('POST', '/v1/assessments/as-http/finalize', {})).status).toBe(200);
    const aview = await view();
    const cred = (await req('GET', '/v1/credentials/' + encodeURIComponent(aview.credentialId))).json;
    const v = (await req('POST', '/v1/verify', { credential: cred })).json;
    expect(v.ok).toBe(true); expect(v.recognition.level).toBe(3);
    // the same chain under a verifier's own, stricter policy
    const strict = (await req('POST', '/v1/verify', { credential: cred, policy: { minAttestors: 4, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8 } })).json;
    expect(strict.recognition.status).toBe('provisional');
    expect((await req('POST', '/v1/verify', { credential: cred, policy: 5 })).status).toBe(400);
    const cp = (await req('GET', '/v1/log/checkpoint')).json;
    expect(cp.payload.size).toBeGreaterThan(4);
    const inc = (await req('GET', '/v1/log/inclusion?index=0')).json; expect(inc.size).toBe(cp.payload.size);
    expect((await req('GET', '/v1/log/consistency?m=2&n=' + cp.payload.size)).json.proof).toBeInstanceOf(Array);
    expect((await req('GET', '/v1/log/entries?from=0&to=3')).json.entries).toHaveLength(3);
    expect((await req('GET', '/v1/log/inclusion?index=9999')).status).toBe(400);
    expect((await req('GET', '/v1/log/entries?from=abc')).status).toBe(400);
    expect((await req('GET', '/v1/attestors/' + encodeURIComponent(P.A.did) + '/stats')).json.sittings).toBe(1);
  });
  it('a forged commit (wrong signer) is refused with 401 and the reason', async () => {
    const { people: P } = ctx;
    const body = { id: 'as-http2', templateId: 'maths-oral-v1', subject: 'urn:uuid:33333333-3333-4333-8333-333333333333', claimedLevel: 2, evidence: [{ key: 'E1', date: '2026-03-01', summary: 's', body: {} }] };
    await op('POST', '/v1/assessments', body);
    const i = (await op('POST', '/v1/assessments/as-http2/invite', { attestor: P.A.did, role: 'examiner', evidence: 'E1' })).json;
    const { request } = prepareCommit({ signer: P.A.signer, assessment: (await req('GET', '/v1/assessments/as-http2')).json, attestationId: i.attestationId, level: 2 });
    request.jws = P.B.signer.sign('sanad-commit+jws', request.payload);
    const r = await req('POST', '/v1/assessments/as-http2/commit', request);
    expect(r.status).toBe(401); expect(r.json.error).toBe('bad_signature');
  });
});
