// The port/adapter pattern for a host (docs/TUTORIAL-plug-sanad-into-any-system.md, section 5).
// The host keeps its own workflow. Exactly one module, this one, talks to Sanad. Which provider runs is a configuration choice:
//   { provider: 'embedded', engine }                       the vendored library in the host process (mode 1)
//   { provider: 'http', url, operatorToken }               a sidecar service (mode 2)
// Both return the same async interface and throw the same errors ({ code, status }), which `test/port-contract.test.mjs` checks for each.
// Verification (mode 3) needs no provider: use verifyCredential directly.
import { verifyCredential } from '../src/index.mjs';

/** The interface a host codes against. Every method is async, whatever the provider. */
export const PORT_METHODS = ['info', 'registerTemplate', 'createAssessment', 'invite', 'uninvite', 'ticket', 'getAssessment', 'commit', 'reveal', 'preview', 'finalize', 'verify', 'checkpoint'];

class SanadError extends Error { constructor(code, message, status) { super(message); this.code = code; this.status = status; } }

export function createEmbeddedProvider({ engine }) {
  const wrap = (f) => async (...a) => { try { return f(...a); } catch (e) { throw new SanadError(e.code ?? 'internal', e.message, e.status ?? 500); } };
  return {
    kind: 'embedded',
    info: wrap(() => engine.info()),
    registerTemplate: wrap((t) => engine.registerTemplate(t)),
    createAssessment: wrap((a) => engine.createAssessment(a)),
    invite: wrap((id, i) => engine.invite(id, i)),
    uninvite: wrap((id, att, reason) => engine.removeInvitation(id, att, { reason })),
    ticket: wrap((id, att) => engine.ticketFor(id, att)),
    getAssessment: wrap((id) => engine.getAssessment(id)),
    commit: wrap((id, req) => engine.commit(id, req)),
    reveal: wrap((id, req) => engine.reveal(id, req)),
    preview: wrap((id, policy) => engine.previewRecognition(id, { policy })),
    finalize: wrap((id) => engine.finalize(id)),
    verify: wrap((doc, opts) => engine.verifyCredential(doc, opts)),
    checkpoint: wrap(() => engine.log.checkpoint()),
  };
}

export function createHttpProvider({ url, operatorToken, timeoutMs = 10000 }) {
  const base = url.replace(/\/$/, '');
  async function call(method, path, body, op = false) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (op) headers.authorization = 'Bearer ' + operatorToken;
    let r;
    try { r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) }); }
    catch (e) { throw new SanadError('provider_unreachable', 'the Sanad provider could not be reached: ' + (e?.message ?? e), 503); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new SanadError(j.error ?? 'http_' + r.status, j.message ?? r.statusText, r.status);
    return j;
  }
  const A = (id) => '/v1/assessments/' + encodeURIComponent(id);
  return {
    kind: 'http',
    info: () => call('GET', '/v1/info'),
    registerTemplate: (t) => call('POST', '/v1/templates', t, true),
    createAssessment: (a) => call('POST', '/v1/assessments', a, true),
    invite: (id, i) => call('POST', A(id) + '/invite', i, true),
    uninvite: (id, att, reason) => call('POST', A(id) + '/invitations/' + encodeURIComponent(att) + '/remove', reason ? { reason } : {}, true),
    ticket: (id, att) => call('GET', A(id) + '/ticket/' + encodeURIComponent(att)),
    getAssessment: (id) => call('GET', A(id)),
    commit: (id, req) => call('POST', A(id) + '/commit', req),
    reveal: (id, req) => call('POST', A(id) + '/reveal', req),
    preview: (id, policy) => call('POST', A(id) + '/preview', policy ? { policy } : {}),
    finalize: (id) => call('POST', A(id) + '/finalize', {}, true),
    verify: (doc, opts = {}) => call('POST', '/v1/verify', { credential: doc, ...opts }),
    checkpoint: () => call('GET', '/v1/log/checkpoint'),
  };
}

/** Chooses the provider from configuration; nothing else in the host changes when the choice changes. */
export function createProvider(config) {
  if (config.provider === 'embedded') return createEmbeddedProvider(config);
  if (config.provider === 'http') return createHttpProvider(config);
  throw new Error('unknown Sanad provider: ' + config.provider);
}

export { verifyCredential };
