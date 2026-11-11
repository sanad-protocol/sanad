// The engine: ties templates, assessments, the transparency log, sealing and verification together (DESIGN.md sections 4 and 12).
// Attestor private keys are never received, stored or generated here; only signed statements arrive.
import { randomBytes, createHash } from 'node:crypto';
import { hashOf, sealEvidence, recognise } from './core.mjs';
import { checkIJson } from './ijson.mjs';
import { EngineError } from './errors.mjs';
import { createResolver, isIsoDate } from './keys.mjs';
import { assertTemplate, templateHash, policyFromTemplate, nativeOfNonce, validatePolicy } from './template.mjs';
import { checkCommit, checkReveal, NONCE_RE } from './commit.mjs';
import { attestorStats } from './stats.mjs';
import { createLog } from './log.mjs';
import { sealBundle, bundleHashOf as hashBundle, buildCredential, verifyCredential as verifyDoc, ATTESTATION_TYP } from './bundle.mjs';

const ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;
const SUBJECT_RE = /^urn:([a-z0-9][a-z0-9-]{0,31}):([^\s]{1,160})$/i;
// A guard rail, not a guarantee: namespaces that are plainly personal are refused, but a URN can still be chosen badly.
const PERSONAL_NS = new Set(['email', 'mailto', 'mail', 'person', 'name', 'tel', 'phone', 'msisdn']);
const subjectOk = (s) => { const m = typeof s === 'string' ? SUBJECT_RE.exec(s) : null; return !!m && !PERSONAL_NS.has(m[1].toLowerCase()) && !m[2].includes('@'); };
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
// a credential id derived from the assessment and the bundle hash, so that a retried finalize overwrites instead of duplicating
const uuidFrom = (text) => { const h = createHash('sha256').update(text).digest('hex'); return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`; };
const DID_KEY = 'did:key:';
const COMMIT_TYP = 'sanad-commit+jws';
const HOUR = 3600000;
const err = (code, message, status = 400) => new EngineError(code, message, status);
const clone = (v) => JSON.parse(JSON.stringify(v));
const isDateTime = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s) && !Number.isNaN(Date.parse(s));

export function createEngine({ store, issuer, logSigner, logId = 'sanad-log', resolver, clock = { now: () => Date.now() } } = {}) {
  if (!store) throw err('bad_config', 'a store is required');
  if (!issuer || !issuer.did || !issuer.kid || typeof issuer.sign !== 'function') throw err('bad_config', 'issuer must be { did, kid, sign }');
  if (!logSigner || !logSigner.did || typeof logSigner.sign !== 'function') throw err('bad_config', 'logSigner must be { did, kid, sign }');
  const res = resolver ?? createResolver({ store });
  const log = createLog({ store, logId, signer: logSigner, clock });
  // the engine's clock never runs backwards: a deadline that has passed stays passed (also across restarts, through each assessment's high-water mark)
  let hi = 0;
  const nowMs = () => { const t = clock.now(); if (Number.isFinite(t) && t > hi) hi = t; return hi; };
  const nowIso = () => new Date(nowMs()).toISOString();
  const today = () => nowIso().slice(0, 10);

  const getRec = (id) => {
    const a = typeof id === 'string' && ID_RE.test(id) ? store.get('assessments', id) : null;
    if (!a) throw err('assessment_unknown', 'no such assessment: ' + id, 404);
    if (Number.isFinite(a.hwm) && a.hwm > hi) hi = a.hwm;
    return a;
  };
  const save = (a) => { a.hwm = Math.max(hi, a.hwm ?? 0); store.put('assessments', a.id, a); };
  const revealOpen = (a) => !!a.revealOpenedAt || Object.keys(a.reveals).length > 0 || (a.invitations.length > 0 && a.invitations.every((i) => a.commits[i.attestationId])) || nowMs() > Date.parse(a.commitBy);
  const sigFail = (r) => { const e = err('bad_signature', 'signature refused: ' + r.reason, 401); e.reason = r.reason; return e; };

  function publicView(a) {
    const open = revealOpen(a) || a.state === 'finalized';
    const commits = {};
    for (const [k, c] of Object.entries(a.commits)) commits[k] = { commit: c.commit, payload: c.payload, jws: c.jws, at: c.at };
    const reveals = {};
    if (open) for (const [k, r] of Object.entries(a.reveals)) reveals[k] = { statement: r.statement, jws: r.jws, at: r.at };
    const { id, templateId, templateHash: th, subject, claimedLevel, evidence, commitBy, revealBy, createdAt, invitations, late, state, credentialId } = a;
    return clone({ id, templateId, templateHash: th, subject, claimedLevel, evidence, commitBy, revealBy, createdAt, invitations, removed: a.removed ?? [], commits, reveals, late, state, credentialId: credentialId ?? null, revealOpen: open });
  }

  let statsMemo = null; // invalidated when an assessment is finalized (single process per store)
  const finalizedStats = (excludeId) => {
    if (excludeId === undefined || excludeId === null) { if (statsMemo) return statsMemo; }
    const records = [];
    for (const a of store.list('assessments')) {
      if (a.state !== 'finalized' || a.id === excludeId) continue;
      const c = store.get('credentials', a.credentialId);
      if (!c) continue;
      const b = c.sanad.bundle;
      records.push({ evidence: b.evidence.map((e) => ({ id: e.id, kind: e.kind })), marks: b.attestations.map((x) => ({ attestor: x.attestor, evidence: x.evidence, level: x.level })) });
    }
    const out = attestorStats(records);
    if (excludeId === undefined || excludeId === null) statsMemo = out;
    return out;
  };

  const engine = {
    registerTemplate(t) {
      checkIJson(t);
      assertTemplate(t);
      const hash = templateHash(t);
      const old = store.get('templates', t.id);
      if (old) {
        if (old.hash !== hash) throw err('template_exists', 'template ' + t.id + ' exists with a different hash', 409);
        return { id: t.id, hash };
      }
      store.put('templates', t.id, { template: clone(t), hash });
      return { id: t.id, hash };
    },
    getTemplate(id) {
      const r = typeof id === 'string' && ID_RE.test(id) ? store.get('templates', id) : null;
      if (!r) throw err('template_unknown', 'no such template: ' + id, 404);
      return clone(r.template);
    },
    listTemplates() { return store.list('templates').map((r) => ({ id: r.template.id, hash: r.hash, title: r.template.title, version: r.template.version })); },

    registerDid(doc) { return res.register(doc); },
    updateDid(did, version, jws) { return res.update(did, version, jws); },

    createAssessment({ templateId, subject, subjectDid, claimedLevel, evidence, commitBy, revealBy, id } = {}) {
      const rec = typeof templateId === 'string' && ID_RE.test(templateId) ? store.get('templates', templateId) : null;
      if (!rec) throw err('template_unknown', 'no such template: ' + templateId, 404);
      const t = rec.template;
      if (!subjectOk(subject)) throw err('bad_subject', 'subject must be a pseudonymous URN such as urn:uuid:<uuid> (no spaces, no personal namespace such as email, person, name or tel); names and contact details do not belong in the engine. This is a guard rail: the host remains responsible for choosing a non-identifying URN');
      if (subjectDid !== undefined && !(typeof subjectDid === 'string' && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(subjectDid) && subjectDid.length <= 200)) throw err('bad_subject', 'subjectDid must be a DID');
      if (!Number.isInteger(claimedLevel) || claimedLevel < 0 || claimedLevel > 5) throw err('bad_assessment', 'claimedLevel must be an integer from 0 to 5');
      const aid = id ?? 'as-' + randomBytes(8).toString('hex');
      if (typeof aid !== 'string' || !ID_RE.test(aid) || aid.length > 150) throw err('bad_assessment', 'id must match ' + ID_RE + ' and be at most 150 characters');
      if (store.get('assessments', aid)) throw err('assessment_exists', 'assessment exists: ' + aid, 409);
      if (!Array.isArray(evidence)) throw err('bad_evidence', 'evidence must be a list');
      checkIJson(evidence);
      const plan = new Map(t.evidence.map((e) => [e.key, e]));
      const keys = evidence.map((e) => e?.key);
      if (keys.length !== plan.size || new Set(keys).size !== keys.length || !keys.every((k) => plan.has(k))) throw err('bad_evidence', 'evidence keys must be exactly ' + [...plan.keys()].join(', '));
      const sealed = [];
      for (const e of evidence) {
        if (e === null || typeof e !== 'object' || Array.isArray(e)) throw err('bad_evidence', 'an evidence item must be an object');
        if (!isIsoDate(e.date)) throw err('bad_evidence', 'evidence ' + e.key + ': date must be YYYY-MM-DD');
        if (typeof e.summary !== 'string') throw err('bad_evidence', 'evidence ' + e.key + ': summary must be a string');
        if (e.body === null || typeof e.body !== 'object' || Array.isArray(e.body)) throw err('bad_evidence', 'evidence ' + e.key + ': body must be an object');
        const kind = plan.get(e.key).kind;
        if (('kind' in e.body && e.body.kind !== kind) || ('date' in e.body && e.body.date !== e.date)) throw err('bad_evidence', 'evidence ' + e.key + ': body.kind and body.date must equal the item kind and date');
        const body = { ...clone(e.body), kind, date: e.date };
        sealed.push(sealEvidence({ id: `${aid}.${e.key}`, kind, date: e.date, summary: e.summary, body }));
      }
      const start = nowMs();
      const cb = commitBy === undefined ? start + t.deadlines.commitHours * HOUR : (isDateTime(commitBy) ? Date.parse(commitBy) : NaN);
      if (Number.isNaN(cb)) throw err('bad_assessment', 'commitBy must be an ISO date-time');
      const rb = revealBy === undefined ? cb + t.deadlines.revealHours * HOUR : (isDateTime(revealBy) ? Date.parse(revealBy) : NaN);
      if (Number.isNaN(rb)) throw err('bad_assessment', 'revealBy must be an ISO date-time');
      if (!(rb > cb)) throw err('bad_assessment', 'revealBy must be after commitBy');
      const a = {
        id: aid, templateId, templateHash: rec.hash, subject, ...(subjectDid ? { subjectDid } : {}), claimedLevel, evidence: sealed,
        commitBy: new Date(cb).toISOString(), revealBy: new Date(rb).toISOString(), createdAt: nowIso(),
        invitations: [], commits: {}, reveals: {}, late: [], state: 'open', credentialId: null,
      };
      save(a);
      return publicView(a);
    },

    invite(assessmentId, { attestor, role, evidence } = {}) {
      const a = getRec(assessmentId);
      const t = engine.getTemplate(a.templateId);
      if (a.state !== 'open') throw err('state', 'the assessment is finalized', 409);
      if (revealOpen(a)) throw err('state', 'the reveal phase is open; no more invitations', 409);
      const ev = a.evidence.find((e) => e.id === evidence || e.id === `${a.id}.${evidence}`);
      if (!ev) throw err('bad_evidence', 'unknown evidence item: ' + evidence);
      if (typeof attestor !== 'string' || !/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(attestor) || attestor.length > 200) throw err('bad_attestor', 'attestor must be a DID');
      if (!t.attestors.roles.includes(role)) throw err('bad_role', 'role must be one of ' + t.attestors.roles.join(', '));
      if (a.subjectDid && attestor === a.subjectDid) throw err('subject_as_attestor', 'the subject cannot attest their own work');
      const same = a.invitations.filter((i) => i.evidence === ev.id);
      if (same.some((i) => i.attestor === attestor)) throw err('duplicate_attestor', 'this attestor is already invited on ' + ev.id, 409);
      const seq = (a.seq ?? a.invitations.length) + 1;
      if (same.length >= t.attestors.max || seq > 99) throw err('too_many_attestors', 'at most ' + t.attestors.max + ' attestors per evidence item', 409);
      if (res.keysAt(attestor, today()).length === 0) throw err('did_unresolvable', 'no valid key for ' + attestor + ' today');
      const inv = { attestationId: `${a.id}.a${String(seq).padStart(2, '0')}`, attestor, role, evidence: ev.id, invitedAt: nowIso() };
      a.invitations.push(inv); a.seq = seq;
      save(a);
      return clone(inv);
    },

    /** Operator action: withdraw an invitation before that attestor's first commit. Never reuses the attestation id; recorded in the events stream and in the credential's process.removed. */
    removeInvitation(assessmentId, attestationId, { reason } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== 'open') throw err('state', 'the assessment is finalized', 409);
      const i = a.invitations.findIndex((x) => x.attestationId === attestationId);
      if (i < 0) throw err('not_invited', 'no invitation ' + attestationId, 404);
      if (a.commits[attestationId]) throw err('already_committed', 'a commit for ' + attestationId + ' exists; an invitation cannot be removed after the first commit', 409);
      if (reason !== undefined && (typeof reason !== 'string' || reason.length > 200)) throw err('bad_reason', 'reason must be a string of up to 200 characters');
      const [inv] = a.invitations.splice(i, 1);
      (a.removed ??= []).push({ attestationId, attestor: inv.attestor, role: inv.role, evidence: inv.evidence, removedAt: nowIso() });
      store.append('events', { type: 'invitation-removed', assessment: a.id, attestationId, attestor: inv.attestor, at: nowIso(), ...(reason ? { reason } : {}) });
      save(a);
      return { removed: attestationId, invited: a.invitations.length };
    },

    commit(assessmentId, { attestationId, payload, jws } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== 'open') throw err('state', 'the assessment is finalized', 409);
      const inv = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv) throw err('not_invited', 'no invitation ' + attestationId, 403);
      if (a.commits[attestationId]) throw err('already_committed', 'a commit for ' + attestationId + ' exists', 409);
      if (a.revealOpenedAt || Object.keys(a.reveals).length > 0 || nowMs() > Date.parse(a.commitBy)) throw err('commit_closed', 'the commit phase is over (deadline ' + a.commitBy + ' or reveals have begun)', 409);
      checkCommit({ payload, invitation: inv, assessment: a });
      const r = res.verifyStatement({ jws, payload, typ: COMMIT_TYP, signer: inv.attestor, date: today() });
      if (!r.ok) throw sigFail(r);
      const entry = log.append({ kind: 'commit', ref: hashOf(payload) });
      a.commits[attestationId] = { commit: payload.commit, payload: clone(payload), jws, at: nowIso(), logIndex: entry.index };
      if (a.invitations.every((i) => a.commits[i.attestationId])) a.revealOpenedAt = nowIso();
      save(a);
      return { committed: Object.keys(a.commits).length, of: a.invitations.length };
    },

    reveal(assessmentId, { attestationId, statement, jws } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== 'open') throw err('state', 'the assessment is finalized', 409);
      const inv = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv) throw err('not_invited', 'no invitation ' + attestationId, 403);
      if (!revealOpen(a)) throw err('reveal_not_open', 'the reveal phase is not open yet', 409);
      const c = a.commits[attestationId];
      if (!c) throw err('not_committed', 'no commit for ' + attestationId, 409);
      if (a.reveals[attestationId]) throw err('already_revealed', attestationId + ' is already revealed', 409);
      if (nowMs() > Date.parse(a.revealBy)) {
        // recorded as late only when the statement is the invited attestor's own, validly signed: nobody can mark another attestor late
        if (statement === null || typeof statement !== 'object' || statement.id !== attestationId || statement.attestor !== inv.attestor || !isIsoDate(statement.date)) throw err('bad_statement', 'a late reveal is recorded only for a statement of the invited attestor');
        const lr = res.verifyStatement({ jws, payload: statement, typ: ATTESTATION_TYP, signer: inv.attestor, date: statement.date });
        if (!lr.ok) throw sigFail(lr);
        if (!a.late.includes(attestationId)) { a.late.push(attestationId); a.late.sort(); save(a); }
        throw err('reveal_late', 'the reveal phase ended at ' + a.revealBy, 409);
      }
      const t = engine.getTemplate(a.templateId);
      checkReveal({
        statement, invitation: inv, storedCommit: c.commit, evidenceDate: a.evidence.find((e) => e.id === inv.evidence).date,
        revealDay: today(), allowedLevels: t.levels.map((l) => l.level),
      });
      const nat = nativeOfNonce(statement.nonce);
      if (nat !== null && t.levelMap) {
        if (!Object.hasOwn(t.levelMap, nat)) throw err('native_unknown', 'the nonce names a native mark that the template levelMap does not list');
        if (t.levelMap[nat] !== statement.level) throw err('native_mismatch', 'the native mark in the nonce maps to a different level than the revealed level');
      }
      const r = res.verifyStatement({ jws, payload: statement, typ: ATTESTATION_TYP, signer: inv.attestor, date: statement.date });
      if (!r.ok) throw sigFail(r);
      a.reveals[attestationId] = { statement: clone(statement), jws, at: nowIso() };
      a.revealOpenedAt ??= nowIso();
      save(a);
      return { revealed: Object.keys(a.reveals).length, of: Object.keys(a.commits).length };
    },

    /**
     * Seals the credential. The template's minimum is enforced: every evidence item that needs human attestors (kind other than auto) must have at least
     * `attestors.min` revealed attestors, and a live-sitting template needs revealed marks on sitting evidence. `allowShortfall: true` is the operator's
     * explicit, recorded override (`process.shortfall`). Retrying after a crash is safe: log leaves are appended once and the credential id is derived.
     */
    finalize(assessmentId, { allowShortfall = false } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== 'open') throw err('state', 'the assessment is already finalized', 409);
      const t = engine.getTemplate(a.templateId);
      const committed = Object.keys(a.commits).sort();
      const allRevealed = committed.every((k) => a.reveals[k]);
      if (!((a.invitations.length > 0 && allRevealed) || nowMs() > Date.parse(a.revealBy))) throw err('not_ready', 'commits are still waiting for their reveals and the reveal deadline has not passed', 409);

      const missing = committed.filter((k) => !a.reveals[k]);
      const notCommitted = a.invitations.map((i) => i.attestationId).filter((k) => !a.commits[k]).sort();
      const revealed = committed.filter((k) => a.reveals[k]);

      // template minimum and live sitting
      const shortfall = [];
      const byEv = new Map(a.evidence.map((e) => [e.id, new Set()]));
      for (const k of revealed) byEv.get(a.reveals[k].statement.evidence)?.add(a.reveals[k].statement.attestor);
      for (const e of a.evidence) if (e.kind !== 'auto' && byEv.get(e.id).size < t.attestors.min) shortfall.push(`${e.id}: ${byEv.get(e.id).size} revealed attestor(s), template minimum ${t.attestors.min}`);
      if (t.liveSitting && !a.evidence.some((e) => e.kind === 'sitting' && byEv.get(e.id).size > 0)) shortfall.push('liveSitting: no sitting evidence has a revealed attestor');
      if (shortfall.length && !allowShortfall) throw err('below_template_minimum', 'the template requirements are not met (' + shortfall.join('; ') + '); pass allowShortfall to finalize anyway, which is recorded in the credential', 409);

      const attestors = [...new Set(revealed.map((k) => a.reveals[k].statement.attestor))];
      const hist = finalizedStats();
      const stats = {};
      for (const d of attestors) stats[d] = has(hist, d) ? hist[d] : { sittings: 0, agreement: 0 };
      const bundle = sealBundle({
        skill: t.skill.id, claimedLevel: a.claimedLevel, subject: a.subject, evidence: a.evidence,
        attestations: revealed.map((k) => ({ statement: a.reveals[k].statement, signature: a.reveals[k].jws })), attestors: stats,
      });
      const bundleHash = hashBundle(bundle);

      const logIdx = committed.map((k) => a.commits[k].logIndex);
      for (const k of missing) logIdx.push(log.appendOnce({ kind: 'missing-reveal', ref: a.commits[k].commit }).index);
      for (const x of bundle.attestations) logIdx.push(log.appendOnce({ kind: 'attestation', ref: x.hash }).index);
      logIdx.push(log.appendOnce({ kind: 'bundle', ref: bundleHash }).index);

      const cp = log.checkpoint();
      const idx = [...new Set(logIdx)].sort((x, y) => x - y);
      const embedded = {
        logId, logKey: logSigner.did,
        entries: idx.map((i) => ({ index: i, leaf: log.entries(i, i + 1)[0].leaf })),
        proofs: idx.map((i) => ({ index: i, size: cp.payload.size, proof: log.inclusion(i, cp.payload.size).proof })),
        checkpoint: cp,
      };
      const dids = [...new Set([issuer.did, logSigner.did, ...attestors])].filter((d) => !d.startsWith(DID_KEY)).map((d) => res.get(d)).filter(Boolean);
      const process = {
        invited: a.invitations.length, committed: committed.length, revealed: revealed.length, missing, late: [...a.late], notCommitted,
        ...((a.removed ?? []).length ? { removed: a.removed.map((r) => r.attestationId).sort() } : {}),
        ...(shortfall.length ? { shortfall } : {}),
      };
      const doc = buildCredential({
        bundle, issuer, template: { id: t.id, hash: a.templateHash }, assessment: a.id, process, policy: t.policy, log: embedded, dids, now: nowMs(),
        id: uuidFrom(a.id + ':' + bundleHash),
      });
      store.put('credentials', doc.id, doc);
      a.state = 'finalized'; a.credentialId = doc.id; a.finalizedAt = nowIso();
      save(a);
      statsMemo = null;
      return clone(doc);
    },

    getAssessment(id, { view = 'public' } = {}) {
      const a = getRec(id);
      return view === 'operator' ? clone(a) : publicView(a);
    },
    getCredential(id) {
      const c = typeof id === 'string' && ID_RE.test(id) ? store.get('credentials', id) : null;
      if (!c) throw err('credential_unknown', 'no such credential: ' + id, 404);
      return c;
    },
    listAssessments() { return store.list('assessments').map((a) => ({ id: a.id, templateId: a.templateId, subject: a.subject, state: a.state, credentialId: a.credentialId ?? null, createdAt: a.createdAt })); },

    verifyCredential(doc, opts = {}) {
      // the engine's own issuer, log key and registered DIDs are the defaults of an operator checking its own output; policy and day are never defaulted
      let template = opts.template;
      if (template === undefined) { try { const tid = doc?.sanad?.template?.id; const rec = typeof tid === 'string' && ID_RE.test(tid) ? store.get('templates', tid) : null; if (rec && rec.hash === doc.sanad.template.hash) template = rec.template; } catch { /* verified without */ } }
      return verifyDoc(doc, { ...opts, resolver: opts.resolver ?? res, trustedIssuers: opts.trustedIssuers ?? [issuer.did], trustedLogKeys: opts.trustedLogKeys ?? [logSigner.did], trustedLogIds: opts.trustedLogIds ?? [logId], ...(template ? { template } : {}) });
    },
    stats(did) {
      const all = finalizedStats(null);
      return did === undefined ? all : (typeof did === 'string' && has(all, did) ? all[did] : { sittings: 0, agreement: 0 });
    },
    log,
    resolver: res,
    info() { return { engine: '0.2.0', alg: 'sanad-0.1', issuer: issuer.did, logId, logKey: logSigner.did, time: nowIso(), today: today() }; },

    /**
     * Read-only preview of recognition over the attestations revealed so far. It never reads an unrevealed mark (a commit holds no readable mark):
     * only the number of attestors still pending is returned. The result is always marked provisional and names whose policy produced it.
     */
    previewRecognition(assessmentId, { policy } = {}) {
      const a = getRec(assessmentId);
      const t = engine.getTemplate(a.templateId);
      if (policy !== undefined && (policy === null || typeof policy !== 'object' || Array.isArray(policy))) throw err('bad_policy', 'policy must be an object');
      const base = policy ? { ...policy } : policyFromTemplate(t, today());
      delete base.id;
      const pol = { ...base, asOf: policy?.asOf ?? today() };
      const pp = validatePolicy(pol);
      if (pp.length) throw err('bad_policy', 'policy refused: ' + pp.join('; '));
      const revealed = Object.keys(a.reveals).sort();
      const hist = finalizedStats(), stats = {};
      for (const k of revealed) { const d = a.reveals[k].statement.attestor; stats[d] = has(hist, d) ? hist[d] : { sittings: 0, agreement: 0 }; }
      const bundle = sealBundle({
        skill: t.skill.id, claimedLevel: a.claimedLevel, subject: a.subject, evidence: a.evidence,
        attestations: revealed.map((k) => ({ statement: a.reveals[k].statement, signature: a.reveals[k].jws })), attestors: stats,
      });
      let recognition;
      try { recognition = recognise(bundle, pol); } catch (e) { throw err('bad_policy', 'the recognition function refused the policy: ' + (e?.message ?? e)); }
      return {
        preview: true, provisional: true, state: a.state,
        policySource: policy ? 'verifier-supplied' : 'template-recommendation',
        counts: { invited: a.invitations.length, committed: Object.keys(a.commits).length, revealed: revealed.length, pending: Object.keys(a.commits).length - revealed.length, notCommitted: a.invitations.length - Object.keys(a.commits).length },
        recognition,
        note: 'Computed only from revealed attestations; marks not yet revealed are not read. Not a credential: the final result can differ once the remaining attestors reveal or the deadline passes.',
      };
    },

    /** What a host hands one attestor's client so it can sign the commit and the attestation (DESIGN section 8a). Contains no secret. */
    ticketFor(assessmentId, attestationId) {
      const a = getRec(assessmentId);
      const inv = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv) throw err('not_invited', 'no invitation ' + attestationId, 404);
      const t = engine.getTemplate(a.templateId);
      const ev = a.evidence.find((e) => e.id === inv.evidence);
      return clone({
        ticketVersion: 1, alg: 'sanad-0.1',
        assessment: a.id, attestationId, attestor: inv.attestor, role: inv.role, evidence: inv.evidence, templateHash: a.templateHash,
        levels: t.levels.map((l) => l.level), ...(t.levelMap ? { levelMap: t.levelMap } : {}),
        commitBy: a.commitBy, revealBy: a.revealBy, state: a.state, revealOpen: revealOpen(a) || a.state === 'finalized',
        serverTime: nowIso(), serverDay: today(),
        rules: {
          nonce: { pattern: NONCE_RE.source, minLength: 22, hint: '16 random bytes as base64url; optional native-mark form nm-<native>-<random> when the template has a levelMap' },
          date: { format: 'YYYY-MM-DD', notBefore: ev.date, notAfter: 'the host day at the moment of the reveal (use serverDay from the same provider)' },
          level: 'integer listed in levels',
        },
        commit: { typ: 'sanad-commit+jws', members: ['type', 'assessment', 'attestationId', 'attestor', 'evidence', 'role', 'commit', 'templateHash'], type: 'sanad-commit', commit: 'sha256(canonical({attestor, evidence, level, nonce})) as 64 lowercase hex', post: `/v1/assessments/${a.id}/commit` },
        attestation: { typ: 'sanad-attestation+jws', members: ['id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'commit', 'nonce'], id: attestationId, post: `/v1/assessments/${a.id}/reveal` },
      });
    },
  };
  return engine;
}
