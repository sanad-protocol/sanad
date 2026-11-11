// Command line of the engine (DESIGN.md section 9). `main(argv, io)` returns an exit code and never calls process.exit.
// Operator commands act on the engine in a data directory (single process: do not run them while `serve` uses the same directory).
// Attestor commands (`keygen`, `commit`, `reveal`) use a key file the attestor keeps; with --url they talk to a running server and send only signed statements.
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, openSync, closeSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createEngine } from './engine.mjs';
import { createFileStore } from './store/file.mjs';
import { generateKeyPair, makeSigner, exportPrivateKey, importPrivateKey } from './keys.mjs';
import { prepareCommit, prepareReveal } from './attestor.mjs';
import { createHttpServer } from './http.mjs';
import { EngineError } from './errors.mjs';
import { NOTICE, verifyCredential } from './bundle.mjs';

const USAGE = `sanad-engine <command>

  init [--dir <dir>]                          create issuer key, log key, operator token and store in <dir> (default ./sanad-data)
  keygen --out <file>                         make an attestor key (demonstration; real attestors keep their own)
  template add <file>                         register a template
  create-assessment --template <id> --subject <id> --level <n> [--evidence <file>] [--commit-by <iso>] [--reveal-by <iso>] [--id <id>]
  invite <assessment> --attestor <did> --evidence <key> [--role <role>]
  commit <assessment> <attestationId> --key <file> --level <n> [--url <server>]
  reveal <assessment> <attestationId> --key <file> [--date <YYYY-MM-DD>] [--conflict] [--url <server>]
  uninvite <assessment> <attestationId> [--reason <text>]   withdraw an invitation before that attestor's first commit
  preview <assessment> [--policy <file>]      provisional recognition over revealed attestations only
  ticket <assessment> <attestationId>         the signing ticket for an attestor's client
  finalize <assessment> [--out <file>] [--allow-shortfall]   (the template minimum is enforced; the override is recorded in the credential)
  verify <credential.json> [--policy <file>] [--as-of <YYYY-MM-DD>] [--issuer <did>] [--log-key <did>] [--log-id <id>]
         [--pin-key <did>=<multibase>] [--dids <histories.json>] [--stats <file>] [--template <file>] [--allow-unpinned] [--allow-issuer-statistics]
         Without --policy the CLI takes the template's recommendation and the credential's date, and says so. Unpinned issuer or log key fails unless --allow-unpinned.
  log checkpoint | log inclusion --index <i> [--size <n>] | log consistency --m <m> [--n <n>]
  serve [--port <n>] [--host <addr>]          start the HTTP API and demonstration page (default 127.0.0.1:8787)

Common option: --dir <dir> (or SANAD_DIR). Exit codes: 0 success, 1 verification failed, 2 error, 64 usage.`;

class Usage extends Error {}

function parse(args) {
  const pos = [], opt = {};
  const bool = new Set(['conflict', 'help', 'allow-shortfall', 'allow-unpinned', 'allow-issuer-statistics']);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (bool.has(k)) opt[k] = true;
      else { if (i + 1 >= args.length) throw new Usage('option ' + a + ' needs a value'); opt[k] = args[++i]; }
    } else pos.push(a);
  }
  return { pos, opt };
}

const readJson = (f) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch (e) { throw new EngineError('bad_file', 'cannot read JSON from ' + f + ': ' + e.message); } };
const writePrivate = (file, text) => { const fd = openSync(file, 'wx', 0o600); try { writeFileSync(fd, text); } finally { closeSync(fd); } chmodSync(file, 0o600); };
const need = (o, k) => { if (o[k] === undefined) throw new Usage('--' + k + ' is required'); return o[k]; };
const asLevel = (s) => { if (!/^[0-5]$/.test(String(s))) throw new Usage('--level must be an integer from 0 to 5'); return Number(s); };

function loadSigner(file) {
  const k = readJson(file);
  if (typeof k.privateKey !== 'string') throw new EngineError('bad_key', file + ' has no privateKey');
  return makeSigner(importPrivateKey(k.privateKey));
}

function openEngine(dir, clock) {
  const need = (f) => { const p = join(dir, f); if (!existsSync(p)) throw new EngineError('not_initialised', dir + ' is not initialised (run: sanad-engine init --dir ' + dir + ')'); return p; };
  const issuer = loadSigner(need('issuer.key.json')), logSigner = loadSigner(need('log.key.json'));
  const store = createFileStore(join(dir, 'store'));
  const engine = createEngine({ store, issuer, logSigner, logId: readJson(need('config.json')).logId, ...(clock ? { clock } : {}) });
  return { engine, store, dir, token: readFileSync(need('operator.token'), 'utf8').trim() };
}

async function call(url, method, path, body) {
  const r = await fetch(url.replace(/\/$/, '') + path, { method, headers: body === undefined ? {} : { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new EngineError(j.error ?? 'http_' + r.status, j.message ?? r.statusText, r.status);
  return j;
}

/** Secrets (level and nonce between commit and reveal) are kept in a file next to the key: <key>.secrets.json, mode 0600. */
function secretsPath(keyFile) { return resolve(keyFile) + '.secrets.json'; }
function readSecrets(keyFile) { const p = secretsPath(keyFile); return existsSync(p) ? readJson(p) : {}; }
function writeSecrets(keyFile, obj) { const p = secretsPath(keyFile); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 }); chmodSync(p, 0o600); }

export async function main(argv, io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(s + '\n'));
  const errOut = io.err ?? ((s) => process.stderr.write(s + '\n'));
  const env = io.env ?? process.env;
  const json = (v) => out(JSON.stringify(v, null, 2));
  try {
    const { pos, opt } = parse(argv);
    const [cmd, ...rest] = pos;
    if (!cmd || opt.help || cmd === 'help') { out(USAGE); return cmd || opt.help ? 0 : 64; }
    const dir = resolve(opt.dir ?? env.SANAD_DIR ?? 'sanad-data');

    if (cmd === 'init') {
      mkdirSync(dir, { recursive: true });
      for (const f of ['issuer.key.json', 'log.key.json', 'operator.token']) if (existsSync(join(dir, f))) throw new EngineError('exists', dir + ' is already initialised');
      const kp1 = generateKeyPair(), kp2 = generateKeyPair();
      const s1 = makeSigner(kp1.privateKey), s2 = makeSigner(kp2.privateKey);
      writePrivate(join(dir, 'issuer.key.json'), JSON.stringify({ did: s1.did, privateKey: exportPrivateKey(kp1.privateKey) }, null, 2) + '\n');
      writePrivate(join(dir, 'log.key.json'), JSON.stringify({ did: s2.did, privateKey: exportPrivateKey(kp2.privateKey) }, null, 2) + '\n');
      writePrivate(join(dir, 'operator.token'), randomBytes(24).toString('base64url') + '\n');
      writeFileSync(join(dir, 'config.json'), JSON.stringify({ logId: 'sanad-log-' + randomBytes(4).toString('hex') }, null, 2) + '\n');
      mkdirSync(join(dir, 'store'), { recursive: true });
      out('initialised ' + dir);
      out('issuer ' + s1.did);
      out('log key ' + s2.did);
      out('operator token in ' + join(dir, 'operator.token') + ' (keep it private)');
      return 0;
    }

    if (cmd === 'keygen') {
      const f = need(opt, 'out');
      const kp = generateKeyPair(), s = makeSigner(kp.privateKey);
      writePrivate(f, JSON.stringify({ did: s.did, privateKey: exportPrivateKey(kp.privateKey) }, null, 2) + '\n');
      out(s.did);
      return 0;
    }

    if (cmd === 'verify') {
      const f = rest[0]; if (!f) throw new Usage('verify needs a credential file');
      const doc = readJson(f);
      const o = {};
      if (opt.policy) o.policy = readJson(opt.policy);
      else { o.useRecommendedPolicy = true; out('NOTE  no --policy given: using the template\'s recommended policy and the credential\'s date as the evaluation day. That is the issuer\'s recommendation, not a verifier policy.'); }
      if (opt['as-of']) o.asOf = opt['as-of'];
      // verify-only mode: no data directory is needed; the verifier pins the issuer and log key (DIDs) and, for did:web identities, the keys
      if (opt.issuer) o.trustedIssuers = [opt.issuer];
      if (opt['log-key']) o.trustedLogKeys = [opt['log-key']];
      if (opt['log-id']) o.trustedLogIds = [opt['log-id']];
      if (opt['pin-key']) { o.pinnedKeys = {}; for (const kv of opt['pin-key'].split(',')) { const i = kv.lastIndexOf('='); if (i < 1) throw new Usage('--pin-key must be <did>=<multibase>'); (o.pinnedKeys[kv.slice(0, i)] ??= []).push(kv.slice(i + 1)); } }
      if (opt.dids) o.trustedDidHistories = readJson(opt.dids);
      if (opt.stats) o.attestorStats = readJson(opt.stats);
      if (opt.template) o.template = readJson(opt.template);
      if (opt['allow-unpinned']) o.allowUnpinned = true;
      if (opt['allow-issuer-statistics']) o.allowIssuerStatistics = true;
      const r = verifyCredential(doc, o);
      for (const c of r.checks) out((c.ok ? 'PASS  ' : 'FAIL  ') + c.name + '  ' + c.detail);
      for (const w of r.warnings) out('WARN  ' + w);
      if (r.recognition) {
        out(`recognition (${r.basis.policySource === 'verifier' ? 'your policy' : 'the issuer\'s recommendation, not a verifier policy'}; evaluation day ${r.recognition.policy.asOf}): status ${r.recognition.status}, level ${r.recognition.level}, confidence ${r.recognition.confidence}`);
        for (const s of r.recognition.explanation) out('  ' + s.rule + '  ' + s.summary);
      }
      out('NOTICE  ' + NOTICE);
      return r.ok ? 0 : 1;
    }

    if (cmd === 'commit' || cmd === 'reveal') {
      const [aid, attId] = rest;
      if (!aid || !attId) throw new Usage(cmd + ' needs <assessment> <attestationId>');
      const keyFile = need(opt, 'key');
      const signer = loadSigner(keyFile);
      let assessment, local = null;
      if (opt.url) assessment = await call(opt.url, 'GET', '/v1/assessments/' + encodeURIComponent(aid));
      else { local = openEngine(dir); assessment = local.engine.getAssessment(aid); }
      try {
        if (cmd === 'commit') {
          const level = asLevel(need(opt, 'level'));
          const { request, secret } = prepareCommit({ signer, assessment, attestationId: attId, level });
          const secrets = readSecrets(keyFile);
          // the secret is written before the commit is sent, so that a crash cannot lose the nonce
          secrets[aid + '/' + attId] = secret; writeSecrets(keyFile, secrets);
          const r = opt.url ? await call(opt.url, 'POST', '/v1/assessments/' + encodeURIComponent(aid) + '/commit', request) : local.engine.commit(aid, request);
          json(r);
        } else {
          const secret = readSecrets(keyFile)[aid + '/' + attId];
          if (!secret) throw new EngineError('bad_secret', 'no stored secret for ' + aid + '/' + attId + ' next to ' + keyFile);
          const date = opt.date ?? new Date().toISOString().slice(0, 10);
          const req = prepareReveal({ signer, assessment, attestationId: attId, secret, date, conflictDeclared: opt.conflict === true });
          const r = opt.url ? await call(opt.url, 'POST', '/v1/assessments/' + encodeURIComponent(aid) + '/reveal', req) : local.engine.reveal(aid, req);
          json(r);
        }
      } finally { local?.store.close(); }
      return 0;
    }

    if (cmd === 'serve') {
      const { engine, token, store } = openEngine(dir);
      const port = opt.port === undefined ? 8787 : Number(opt.port);
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Usage('--port must be 0..65535');
      const host = opt.host ?? '127.0.0.1';
      const server = createHttpServer({ engine, operatorToken: token });
      await new Promise((ok, bad) => { server.once('error', bad); server.listen(port, host, ok); });
      const addr = server.address();
      out(`sanad-engine listening on http://${host}:${addr.port} (data ${dir})`);
      if (io.onServer) io.onServer(server, store);
      else await new Promise((ok) => { for (const s of ['SIGINT', 'SIGTERM']) process.once(s, () => server.close(() => { store.close(); ok(); })); });
      return 0;
    }

    // remaining commands act on the engine in the data directory
    const ctx = openEngine(dir, io.clock);
    try {
      const { engine } = ctx;
      if (cmd === 'template' && rest[0] === 'add') { if (!rest[1]) throw new Usage('template add needs a file'); json(engine.registerTemplate(readJson(rest[1]))); return 0; }
      if (cmd === 'create-assessment') {
        const args = { templateId: need(opt, 'template'), subject: need(opt, 'subject'), claimedLevel: asLevel(need(opt, 'level')) };
        args.evidence = opt.evidence ? readJson(opt.evidence) : [];
        for (const [k, n] of [['commit-by', 'commitBy'], ['reveal-by', 'revealBy'], ['id', 'id']]) if (opt[k] !== undefined) args[n] = opt[k];
        json(engine.createAssessment(args)); return 0;
      }
      if (cmd === 'invite') {
        const aid = rest[0]; if (!aid) throw new Usage('invite needs an assessment id');
        const a = engine.getAssessment(aid);
        const role = opt.role ?? engine.getTemplate(a.templateId).attestors.roles[0];
        json(engine.invite(aid, { attestor: need(opt, 'attestor'), role, evidence: need(opt, 'evidence') })); return 0;
      }
      if (cmd === 'uninvite') { if (!rest[0] || !rest[1]) throw new Usage('uninvite needs <assessment> <attestationId>'); json(engine.removeInvitation(rest[0], rest[1], { reason: opt.reason })); return 0; }
      if (cmd === 'preview') { if (!rest[0]) throw new Usage('preview needs an assessment id'); json(engine.previewRecognition(rest[0], { policy: opt.policy ? readJson(opt.policy) : undefined })); return 0; }
      if (cmd === 'ticket') { if (!rest[0] || !rest[1]) throw new Usage('ticket needs <assessment> <attestationId>'); json(engine.ticketFor(rest[0], rest[1])); return 0; }
      if (cmd === 'finalize') {
        const aid = rest[0]; if (!aid) throw new Usage('finalize needs an assessment id');
        const doc = engine.finalize(aid, { allowShortfall: opt['allow-shortfall'] === true });
        if (opt.out) { writeFileSync(opt.out, JSON.stringify(doc, null, 2) + '\n'); out('credential ' + doc.id + ' written to ' + opt.out); } else json(doc);
        if (doc.sanad.process.shortfall) errOut('WARN  finalized below the template minimum (recorded in the credential): ' + doc.sanad.process.shortfall.join('; '));
        errOut('NOTICE  ' + NOTICE);
        return 0;
      }
      if (cmd === 'log') {
        const sub = rest[0], n = (k) => (opt[k] === undefined ? undefined : Number(opt[k]));
        if (sub === 'checkpoint') { json(engine.log.checkpoint()); return 0; }
        if (sub === 'inclusion') { json(engine.log.inclusion(Number(need(opt, 'index')), n('size'))); return 0; }
        if (sub === 'consistency') { json(engine.log.consistency(Number(need(opt, 'm')), n('n'))); return 0; }
        throw new Usage('log needs checkpoint, inclusion or consistency');
      }
      throw new Usage('unknown command: ' + cmd);
    } finally { ctx.store.close(); }
  } catch (e) {
    if (e instanceof Usage) { errOut(e.message); errOut(USAGE); return 64; }
    if (e instanceof EngineError) { errOut('error ' + e.code + ': ' + e.message); return 2; }
    errOut('error: ' + (e?.message ?? e));
    return 2;
  }
}
