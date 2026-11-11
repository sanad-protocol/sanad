// HTTP API of the engine (DESIGN.md section 8): JSON over node:http, no dependencies.
// Operator routes need a bearer token. Attestor routes are open because their bodies are signed statements.
// The server never receives an attestor's private key: only commits and reveals that the attestor signed elsewhere.
import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EngineError } from './errors.mjs';
import { scanJsonText, checkIJson } from './ijson.mjs';
import { VERIFY_LIMITS } from './bundle.mjs';

export const BODY_LIMIT = 256 * 1024;
const HERE = dirname(fileURLToPath(import.meta.url));
export const STATIC_DIR = join(HERE, '../static');
const FILES = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/sanad-client.js': ['sanad-client.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const SECURITY = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cache-control': 'no-store' };
const MAX_ENTRIES = 1000;
const DRAIN_LIMIT = 1024 * 1024;

const err = (code, message, status = 400) => new EngineError(code, message, status);
const sha = (s) => createHash('sha256').update(s).digest();
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function readBody(req) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') return reject(err('unsupported_media_type', 'content-type must be application/json', 415));
    const chunks = []; let n = 0; let dead = false;
    req.on('data', (c) => {
      n += c.length;
      if (dead) { if (n > BODY_LIMIT + DRAIN_LIMIT) req.destroy(); return; } // after a refusal, read a little more, then drop the connection
      if (n > BODY_LIMIT) { dead = true; reject(err('body_too_large', 'the body is larger than ' + BODY_LIMIT + ' bytes', 413)); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (dead) return;
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); } catch { return reject(err('bad_json', 'the body is not valid UTF-8')); }
      try { scanJsonText(text); } catch (e) { return reject(e); }
      let v;
      try { v = JSON.parse(text); } catch { return reject(err('bad_json', 'the body is not valid JSON')); }
      try { checkIJson(v); } catch (e) { return reject(e); }
      resolve(v);
    });
    req.on('error', () => { if (!dead) { dead = true; reject(err('bad_request', 'the request could not be read')); } });
  });
}

const intParam = (q, name, def) => {
  const v = q.get(name);
  if (v === null) return def;
  if (!/^\d{1,9}$/.test(v)) throw err('bad_query', name + ' must be a non-negative integer');
  return Number(v);
};

/**
 * @param {{ engine: object, operatorToken: string, staticDir?: string|null, serveStatic?: boolean }} opts
 * @returns {import('node:http').Server}
 */
export function createHttpServer({ engine, operatorToken, serveStatic = true, onError = (m) => process.stderr.write(m + '\n') } = {}) {
  if (!engine) throw err('bad_config', 'an engine is required');
  if (typeof operatorToken !== 'string' || operatorToken.length < 16) throw err('bad_config', 'operatorToken must be a string of at least 16 characters');
  const tokenHash = sha(operatorToken);
  const staticCache = new Map();
  const staticFile = (name) => { if (!staticCache.has(name)) staticCache.set(name, readFileSync(join(STATIC_DIR, name))); return staticCache.get(name); };

  const operator = (req) => {
    const h = String(req.headers.authorization ?? '');
    const m = /^Bearer (.+)$/.exec(h);
    if (!m || !timingSafeEqual(sha(m[1]), tokenHash)) throw err('unauthorized', 'a valid operator token is required', 401);
  };

  // [method, pattern, handler]; :id captures one decoded path segment
  const routes = [];
  const route = (method, path, handler, op = false) => routes.push({ method, parts: path.split('/').slice(1), handler, op });

  route('GET', '/healthz', () => ({ ok: true }));
  route('GET', '/v1/info', () => engine.info());
  route('POST', '/v1/templates', ({ body }) => engine.registerTemplate(body), true);
  route('GET', '/v1/templates', () => engine.listTemplates());
  route('GET', '/v1/templates/:id', ({ p }) => engine.getTemplate(p.id));
  route('POST', '/v1/dids', ({ body }) => {
    if (isObj(body) && 'did' in body && 'version' in body && 'jws' in body) return engine.updateDid(body.did, body.version, body.jws);
    return engine.registerDid(body);
  }, true);
  route('GET', '/v1/dids/:did', ({ p }) => { const d = engine.resolver.get(p.did); if (!d) throw err('did_unknown', 'DID not registered: ' + p.did, 404); return d; });
  route('POST', '/v1/assessments', ({ body }) => engine.createAssessment(body), true);
  route('GET', '/v1/assessments', () => engine.listAssessments(), true);
  route('GET', '/v1/assessments/:id', ({ p }) => engine.getAssessment(p.id));
  route('POST', '/v1/assessments/:id/invite', ({ p, body }) => engine.invite(p.id, body), true);
  route('GET', '/v1/assessments/:id/ticket/:att', ({ p }) => engine.ticketFor(p.id, p.att));
  route('POST', '/v1/assessments/:id/preview', ({ p, body }) => {
    if (!isObj(body)) throw err('bad_request', 'the body must be an object, optionally { policy }');
    return engine.previewRecognition(p.id, { policy: body.policy });
  });
  route('POST', '/v1/assessments/:id/invitations/:att/remove', ({ p, body }) => engine.removeInvitation(p.id, p.att, { reason: isObj(body) ? body.reason : undefined }), true);
  route('POST', '/v1/assessments/:id/commit', ({ p, body }) => engine.commit(p.id, body));
  route('POST', '/v1/assessments/:id/reveal', ({ p, body }) => engine.reveal(p.id, body));
  route('POST', '/v1/assessments/:id/finalize', ({ p, body }) => engine.finalize(p.id, { allowShortfall: isObj(body) && body.allowShortfall === true }), true);
  route('GET', '/v1/credentials/:id', ({ p }) => engine.getCredential(p.id));
  route('POST', '/v1/verify', ({ body }) => {
    if (!isObj(body) || !('credential' in body)) throw err('bad_request', 'the body must be { credential, policy | useRecommendedPolicy, asOf?, trustedIssuers?, trustedLogKeys?, ... } (DESIGN section 8)');
    const c = body.credential, b = c?.sanad?.bundle, l = c?.sanad?.log;
    if ((Array.isArray(b?.attestations) && b.attestations.length > VERIFY_LIMITS.attestations) || (Array.isArray(b?.evidence) && b.evidence.length > VERIFY_LIMITS.evidence)
      || (Array.isArray(l?.entries) && l.entries.length > VERIFY_LIMITS.logEntries) || (Array.isArray(c?.sanad?.dids) && c.sanad.dids.length > VERIFY_LIMITS.dids)) throw err('too_large', 'the credential has more attestations, evidence items, log entries or DID histories than one verification call accepts');
    const opts = {};
    if (body.policy !== undefined) { if (!isObj(body.policy)) throw err('bad_request', 'policy must be an object'); opts.policy = body.policy; }
    for (const k of ['trustedIssuers', 'trustedLogKeys', 'trustedLogIds', 'allowedAttestors']) {
      if (body[k] === undefined) continue;
      if (!Array.isArray(body[k]) || !body[k].every((x) => typeof x === 'string')) throw err('bad_request', k + ' must be a list of strings');
      opts[k] = body[k];
    }
    for (const k of ['useRecommendedPolicy', 'useVerifierClock', 'allowUnpinned', 'allowIssuerStatistics', 'allowEmbeddedDids']) {
      if (body[k] === undefined) continue;
      if (typeof body[k] !== 'boolean') throw err('bad_request', k + ' must be true or false');
      opts[k] = body[k];
    }
    for (const k of ['pinnedKeys', 'attestorStats']) { if (body[k] === undefined) continue; if (!isObj(body[k])) throw err('bad_request', k + ' must be an object'); opts[k] = body[k]; }
    if (body.trustedDidHistories !== undefined) { if (!Array.isArray(body.trustedDidHistories)) throw err('bad_request', 'trustedDidHistories must be a list'); opts.trustedDidHistories = body.trustedDidHistories; }
    if (body.asOf !== undefined) { if (typeof body.asOf !== 'string') throw err('bad_request', 'asOf must be a string'); opts.asOf = body.asOf; }
    return engine.verifyCredential(c, opts);
  });
  route('GET', '/v1/log/checkpoint', () => engine.log.checkpoint());
  route('GET', '/v1/log/entries', ({ q }) => {
    const size = engine.log.size();
    const from = intParam(q, 'from', 0), to = Math.min(intParam(q, 'to', size), size, from + MAX_ENTRIES);
    if (from > to) throw err('bad_query', 'from must not exceed to');
    return { size, from, to, entries: engine.log.entries(from, to) };
  });
  route('GET', '/v1/log/inclusion', ({ q }) => {
    const index = intParam(q, 'index', null);
    if (index === null) throw err('bad_query', 'index is required');
    const size = intParam(q, 'size', engine.log.size());
    if (size > engine.log.size() || index >= size) throw err('bad_query', 'index and size must lie inside the log');
    return engine.log.inclusion(index, size);
  });
  route('GET', '/v1/log/consistency', ({ q }) => {
    const m = intParam(q, 'm', null);
    if (m === null) throw err('bad_query', 'm is required');
    const n = intParam(q, 'n', engine.log.size());
    if (n > engine.log.size() || m > n) throw err('bad_query', 'm and n must satisfy m <= n <= log size');
    return engine.log.consistency(m, n);
  });
  route('GET', '/v1/attestors/:did/stats', ({ p }) => engine.stats(p.did));

  const match = (method, segs) => {
    let pathSeen = false;
    for (const r of routes) {
      if (r.parts.length !== segs.length) continue;
      const p = {};
      let ok = true;
      for (let i = 0; i < segs.length; i++) {
        if (r.parts[i].startsWith(':')) p[r.parts[i].slice(1)] = segs[i];
        else if (r.parts[i] !== segs[i]) { ok = false; break; }
      }
      if (!ok) continue;
      pathSeen = true;
      if (r.method === method) return { r, p };
    }
    return pathSeen ? 'method' : null;
  };

  const send = (res, status, body, headers = {}) => {
    const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    res.writeHead(status, { ...SECURITY, 'content-length': Buffer.byteLength(data), ...headers });
    res.end(data);
  };

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const method = req.method ?? 'GET';
      if (serveStatic && method === 'GET' && FILES[url.pathname]) {
        const [name, type] = FILES[url.pathname];
        return send(res, 200, staticFile(name), { 'content-type': type, 'content-security-policy': CSP });
      }
      let segs;
      try { segs = url.pathname.split('/').slice(1).map((s) => decodeURIComponent(s)); } catch { throw err('bad_path', 'the path is not valid'); }
      const m = match(method, segs);
      if (m === null) throw err('not_found', 'no such route', 404);
      if (m === 'method') throw err('method_not_allowed', 'method not allowed', 405);
      if (m.r.op) operator(req);
      const body = method === 'POST' ? await readBody(req) : undefined;
      const out = await m.r.handler({ p: m.p, q: url.searchParams, body, req });
      return send(res, 200, out, { 'content-type': 'application/json; charset=utf-8' });
    } catch (e) {
      const known = e instanceof EngineError;
      const status = known ? e.status : 500;
      const payload = known ? { error: e.code, message: e.message } : { error: 'internal', message: 'internal error' };
      if (known && e.reason) payload.reason = e.reason;
      if (!known) { try { onError('sanad-engine internal error: ' + (e?.name ?? 'Error') + ': ' + String(e?.message ?? e).slice(0, 200)); } catch { /* logging must not fail the request */ } }
      if (status === 413) res.once('finish', () => req.destroy());
      if (!res.headersSent) send(res, status, payload, { 'content-type': 'application/json; charset=utf-8', ...(status === 413 ? { connection: 'close' } : {}) });
      else res.end();
    }
  });
}
