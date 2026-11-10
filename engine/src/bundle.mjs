// Evidence chain, credential sealing, bundle hash, issuer proof and the credential verifier. Format: DESIGN.md section 3.
import { randomUUID } from 'node:crypto';
import { canonical, hashOf, attestationHashOf, attestationPayload, recognise, infer, SANAD_VERSION } from './core.mjs';
import { createResolver } from './keys.mjs';
import { leafHash, leafBytes, verifyInclusion, verifyCheckpoint } from './log.mjs';

const DID_KEY = 'did:key:';
const KINDS = ['auto', 'sitting', 'artifact', 'peer'];
const HEX64 = /^[0-9a-f]{64}$/;
const ISO_DT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const clone = (v) => JSON.parse(JSON.stringify(v));
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const exactly = (o, names) => { if (!isObj(o)) return false; const k = Object.keys(o).sort(); const n = [...names].sort(); return k.length === n.length && k.every((x, i) => x === n[i]); };

export const CREDENTIAL_TYP = 'sanad-credential+jws';
export const ATTESTATION_TYP = 'sanad-attestation+jws';

/**
 * Seals a bundle: evidence and attestations in id order, the attestation chain from GENESIS, every hash.
 * @param {{ skill: string, claimedLevel: number, subject: string, evidence: object[], attestations: { statement: object, signature: string }[], attestors: object }} p
 */
export function sealBundle({ skill, claimedLevel, subject, evidence, attestations, attestors }) {
  const atts = [];
  let prev = 'GENESIS';
  for (const { statement: s, signature } of [...attestations].sort((a, b) => byId(a.statement, b.statement))) {
    const base = { id: s.id, attestor: s.attestor, evidence: s.evidence, level: s.level, role: s.role, conflictDeclared: s.conflictDeclared, date: s.date, commit: s.commit, nonce: s.nonce, prev };
    const hash = attestationHashOf(base);
    atts.push({ ...base, signature, hash });
    prev = hash;
  }
  return clone({ skill, claimedLevel, subject, evidence: [...evidence].sort(byId), attestations: atts, attestors: attestors ?? {} });
}

/** SHA-256 over the canonical form of { alg, skill, claimedLevel, subject, evidence, attestations } with both lists in id order. */
export function bundleHashOf(bundle) {
  return hashOf({
    alg: SANAD_VERSION, skill: bundle.skill, claimedLevel: bundle.claimedLevel, subject: bundle.subject,
    evidence: [...bundle.evidence].sort(byId), attestations: [...bundle.attestations].sort(byId),
  });
}

/**
 * Builds and signs the credential document.
 * @param {{ bundle: object, issuer: { did: string, kid: string, sign: Function }, template: { id: string, hash: string }, assessment: string, process: object, policy: object, log: object, dids?: object[], now: number|string|Date, id?: string }} p
 */
export function buildCredential({ bundle, issuer, template, assessment, process, policy, log, dids = [], now, id }) {
  const validFrom = new Date(now).toISOString();
  const bundleHash = bundleHashOf(bundle);
  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'SanadCredential'],
    id: id ?? 'urn:uuid:' + randomUUID(),
    issuer: issuer.did,
    validFrom,
    credentialSubject: { id: bundle.subject, skill: bundle.skill, claimedLevel: bundle.claimedLevel },
    evidence: [{ type: ['Evidence', 'SanadBundle'], id: 'urn:sanad:bundle:' + bundleHash, bundleHash, alg: SANAD_VERSION }],
    sanad: { bundle: clone(bundle), template: { id: template.id, hash: template.hash }, assessment, process: clone(process), policy: clone(policy), log: clone(log), dids: clone(dids) },
  };
  const jws = issuer.sign(CREDENTIAL_TYP, clone(doc));
  return { ...doc, proof: { type: 'SanadDetachedJws', verificationMethod: issuer.kid, created: validFrom, jws } };
}

// ---------------------------------------------------------------------------------------------------------------------
// Verification

const POLICY_KEYS = ['minAttestors', 'requireLive', 'halfLifeMonths', 'minAttestorSittings', 'minAgreement', 'maxInferenceDepth', 'inferenceDecay'];

/** Closed member sets everywhere; returns a list of problems (empty when the document has the exact shape). */
function shapeProblems(doc) {
  const p = [];
  const need = (cond, msg) => { if (!cond) p.push(msg); };
  if (!exactly(doc, ['@context', 'type', 'id', 'issuer', 'validFrom', 'credentialSubject', 'evidence', 'sanad', 'proof'])) {
    p.push('top level members must be exactly @context, type, id, issuer, validFrom, credentialSubject, evidence, sanad, proof');
    return p;
  }
  need(canonical(doc['@context']) === canonical(['https://www.w3.org/ns/credentials/v2']), '@context is not the VC 2.0 context');
  need(canonical(doc.type) === canonical(['VerifiableCredential', 'SanadCredential']), 'type is not VerifiableCredential, SanadCredential');
  need(isStr(doc.id) && /^urn:uuid:[0-9a-f-]{36}$/.test(doc.id), 'id is not a urn:uuid');
  need(isStr(doc.issuer) && doc.issuer.startsWith('did:'), 'issuer is not a DID');
  need(isStr(doc.validFrom) && ISO_DT.test(doc.validFrom) && !Number.isNaN(Date.parse(doc.validFrom)), 'validFrom is not an ISO date-time in UTC');
  need(exactly(doc.credentialSubject, ['id', 'skill', 'claimedLevel']), 'credentialSubject members');
  need(Array.isArray(doc.evidence) && doc.evidence.length === 1 && exactly(doc.evidence[0], ['type', 'id', 'bundleHash', 'alg']), 'evidence must be one bundle reference with type, id, bundleHash, alg');
  need(exactly(doc.proof, ['type', 'verificationMethod', 'created', 'jws']), 'proof members');
  const s = doc.sanad;
  if (!exactly(s, ['bundle', 'template', 'assessment', 'process', 'policy', 'log', 'dids'])) { p.push('sanad members must be exactly bundle, template, assessment, process, policy, log, dids'); return p; }
  need(exactly(s.template, ['id', 'hash']), 'sanad.template members');
  need(isStr(s.assessment), 'sanad.assessment must be a string');
  need(exactly(s.process, ['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted']), 'sanad.process members');
  need(exactly(s.policy, ['id', ...POLICY_KEYS]), 'sanad.policy members');
  need(Array.isArray(s.dids) && s.dids.every((d) => exactly(d, ['id', 'versions']) && isStr(d.id) && Array.isArray(d.versions)), 'sanad.dids must be a list of { id, versions }');
  const l = s.log;
  need(exactly(l, ['logId', 'logKey', 'entries', 'proofs', 'checkpoint']) && Array.isArray(l.entries) && Array.isArray(l.proofs)
    && l.entries.every((e) => exactly(e, ['index', 'leaf'])) && l.proofs.every((e) => exactly(e, ['index', 'size', 'proof'])) && exactly(l.checkpoint, ['payload', 'jws']), 'sanad.log members');
  const b = s.bundle;
  if (!exactly(b, ['skill', 'claimedLevel', 'subject', 'evidence', 'attestations', 'attestors'])) { p.push('bundle members must be exactly skill, claimedLevel, subject, evidence, attestations, attestors'); return p; }
  need(isStr(b.skill) && isStr(b.subject) && Number.isInteger(b.claimedLevel), 'bundle skill, subject and claimedLevel types');
  if (!Array.isArray(b.evidence) || !Array.isArray(b.attestations) || !isObj(b.attestors)) { p.push('bundle evidence and attestations must be lists, attestors an object'); return p; }
  b.evidence.forEach((e, i) => {
    if (!exactly(e, ['id', 'kind', 'date', 'summary', 'body', 'hash'])) p.push(`evidence[${i}] members must be exactly id, kind, date, summary, body, hash`);
    else if (!isStr(e.id) || !KINDS.includes(e.kind) || !isStr(e.date) || !isStr(e.summary) || !isObj(e.body) || !isStr(e.hash)) p.push(`evidence[${i}] member types`);
  });
  b.attestations.forEach((a, i) => {
    if (!exactly(a, ['id', 'attestor', 'evidence', 'level', 'role', 'conflictDeclared', 'date', 'signature', 'commit', 'nonce', 'prev', 'hash'])) p.push(`attestations[${i}] members must be exactly the twelve of the reference shape`);
    else if (!['id', 'attestor', 'evidence', 'role', 'date', 'signature', 'commit', 'nonce', 'prev', 'hash'].every((k) => isStr(a[k])) || !Number.isInteger(a.level) || typeof a.conflictDeclared !== 'boolean') p.push(`attestations[${i}] member types`);
  });
  for (const [did, st] of Object.entries(b.attestors)) if (!exactly(st, ['sittings', 'agreement']) || typeof st.sittings !== 'number' || typeof st.agreement !== 'number') p.push(`attestors.${did} must be { sittings, agreement }`);
  if (new Set(b.evidence.map((e) => e.id)).size !== b.evidence.length) p.push('duplicate evidence id');
  if (new Set(b.attestations.map((a) => a.id)).size !== b.attestations.length) p.push('duplicate attestation id');
  return p;
}

/** A resolver for verification: the caller's resolver for DIDs it knows, otherwise the DID histories embedded in the credential. */
function verifierResolver(given, dids) {
  const embedded = new Map();
  for (const d of Array.isArray(dids) ? dids : []) if (isObj(d) && isStr(d.id)) embedded.set(d.id, d);
  const emb = createResolver({ store: { get: (c, id) => embedded.get(id) ?? null, put() {} } });
  const pick = (did) => (given && typeof given.get === 'function' && isStr(did) && !did.startsWith(DID_KEY) && given.get(did) ? given : emb);
  return {
    keysAt(did, date) { try { return pick(did).keysAt(did, date); } catch { return []; } },
    verifyStatement(arg) { try { return pick(arg.signer).verifyStatement(arg); } catch { return { ok: false, reason: 'bad_did_history' }; } },
  };
}

const ADD = (checks, name, ok, detail) => checks.push({ name, ok, detail });

/**
 * Verifies a credential document. Never throws.
 * @param {unknown} doc
 * @param {{ policy?: object, resolver?: object, trustedIssuers?: string[], trustedLogKeys?: string[], asOf?: string, graph?: object }} [opts]
 * @returns {{ ok: boolean, checks: { name: string, ok: boolean, detail: string }[], recognition: object|null, inferred: object[], warnings: string[] }}
 */
export function verifyCredential(doc, opts = {}) {
  const checks = [], warnings = [];
  let recognition = null, inferred = [];
  const done = () => ({ ok: checks.every((c) => c.ok), checks, recognition, inferred, warnings });
  try {
    if (!isObj(doc)) { ADD(checks, 'shape', false, 'the credential must be a JSON object'); return done(); }
    const problems = shapeProblems(doc);
    ADD(checks, 'shape', problems.length === 0, problems.length ? problems.join('; ') : 'closed member sets everywhere; no unknown members');
    if (problems.length) return done();

    const { sanad } = doc, bundle = sanad.bundle;
    const resolver = verifierResolver(opts.resolver, sanad.dids);
    const day = new Date(doc.validFrom).toISOString().slice(0, 10);

    // issuer proof
    {
      const { proof } = doc, { proof: _omit, ...body } = doc;
      const r = proof.type === 'SanadDetachedJws' ? resolver.verifyStatement({ jws: proof.jws, payload: body, typ: CREDENTIAL_TYP, signer: doc.issuer, date: day }) : { ok: false, reason: 'unknown_proof_type' };
      const kidOk = r.ok && r.kid === proof.verificationMethod;
      ADD(checks, 'issuer-proof', r.ok && kidOk && proof.created === doc.validFrom,
        r.ok ? (kidOk ? (proof.created === doc.validFrom ? `signed by ${r.kid}, valid on ${day}` : 'proof.created differs from validFrom') : 'verificationMethod differs from the signing key') : 'issuer signature refused: ' + r.reason);
    }

    // bundle hash
    {
      const h = bundleHashOf(bundle), ref = doc.evidence[0];
      const why = [];
      if (h !== ref.bundleHash) why.push(`recomputed ${h} differs from evidence[0].bundleHash`);
      if (ref.id !== 'urn:sanad:bundle:' + ref.bundleHash) why.push('evidence[0].id does not name the bundle hash');
      if (ref.alg !== SANAD_VERSION) why.push('alg is not ' + SANAD_VERSION);
      if (canonical(doc.credentialSubject) !== canonical({ id: bundle.subject, skill: bundle.skill, claimedLevel: bundle.claimedLevel })) why.push('credentialSubject differs from the bundle');
      ADD(checks, 'bundle-hash', why.length === 0, why.length ? why.join('; ') : 'bundle hash ' + h);
    }

    // evidence kind and date are mirrored into the hashed body
    {
      const bad = bundle.evidence.filter((e) => e.body.kind !== e.kind || e.body.date !== e.date).map((e) => e.id);
      ADD(checks, 'evidence-consistency', bad.length === 0, bad.length ? 'kind or date differs from the hashed body in: ' + bad.join(', ') : 'kind and date equal the hashed body in every evidence item');
    }

    // attestor signatures
    const sigReason = (a) => {
      const { prev: _p, ...stmt } = attestationPayload(a);
      return resolver.verifyStatement({ jws: a.signature, payload: stmt, typ: ATTESTATION_TYP, signer: a.attestor, date: a.date });
    };
    {
      const bad = [];
      for (const a of bundle.attestations) { const r = sigReason(a); if (!r.ok) bad.push(`${a.id} (${r.reason})`); }
      ADD(checks, 'attestor-signatures', bad.length === 0, bad.length ? 'signature refused: ' + bad.join(', ') : `${bundle.attestations.length} attestor signature(s) verify on their dates`);
    }

    // transparency log
    {
      const l = sanad.log, why = [];
      const cp = l.checkpoint;
      const sigOk = verifyCheckpoint(cp, (jws, payload, typ) => resolver.verifyStatement({ jws, payload, typ, signer: l.logKey, date: String(payload.timestamp).slice(0, 10) }).ok);
      if (!sigOk) why.push('checkpoint signature does not verify with the log key');
      if (sigOk && cp.payload.logId !== l.logId) why.push('checkpoint logId differs from the log id');
      const leaves = new Map(); // kind:ref -> true
      if (sigOk) {
        for (const e of l.entries) {
          let parsed;
          try { parsed = JSON.parse(e.leaf); leafBytes(parsed); if (canonical(parsed) !== e.leaf) throw new Error('not canonical'); } catch { why.push(`entry ${e.index}: the leaf is not a valid canonical leaf`); continue; }
          const pr = l.proofs.find((x) => x.index === e.index);
          if (!pr || pr.size !== cp.payload.size) { why.push(`entry ${e.index}: no inclusion proof for the checkpoint size`); continue; }
          if (!verifyInclusion({ leafHash: leafHash(e.leaf), index: e.index, size: pr.size, proof: pr.proof, root: cp.payload.rootHash })) { why.push(`entry ${e.index}: inclusion proof does not match the checkpoint root`); continue; }
          leaves.set(parsed.kind + ':' + parsed.ref, true);
        }
        for (const a of bundle.attestations) if (!leaves.has('attestation:' + a.hash)) why.push(`attestation ${a.id} is not a verified leaf of the log`);
        if (!leaves.has('bundle:' + doc.evidence[0].bundleHash)) why.push('the bundle hash is not a verified leaf of the log');
      }
      if (Array.isArray(opts.trustedLogKeys)) { if (!opts.trustedLogKeys.includes(l.logKey)) why.push('log key ' + l.logKey + ' is not among the trusted log keys'); }
      else warnings.push('log key not pinned');
      ADD(checks, 'log', why.length === 0, why.length ? why.join('; ') : `${l.entries.length} embedded entr${l.entries.length === 1 ? 'y' : 'ies'} verified against the checkpoint of size ${cp.payload.size}; every attestation hash and the bundle hash are leaves`);
    }

    // trusted issuer
    if (Array.isArray(opts.trustedIssuers)) {
      const ok = opts.trustedIssuers.includes(doc.issuer);
      ADD(checks, 'trusted-issuer', ok, ok ? 'issuer is trusted: ' + doc.issuer : 'issuer ' + doc.issuer + ' is not among the trusted issuers');
    } else warnings.push('issuer not pinned');

    // recognition under the verifier's policy
    try {
      const base = opts.policy ? { ...opts.policy } : { ...sanad.policy };
      delete base.id;
      const policy = { ...base, asOf: opts.policy?.asOf ?? opts.asOf ?? day };
      recognition = recognise(bundle, policy, { verifySignature: (a) => sigReason(a).ok });
      if (opts.graph && recognition.status !== 'not-recognised') inferred = infer(opts.graph, bundle.skill, recognition.level, recognition.confidence, policy, [bundle.skill]);
    } catch (e) { ADD(checks, 'recognition', false, 'the recognition function refused the policy: ' + (e?.message ?? e)); }
  } catch (e) {
    ADD(checks, 'internal', false, 'verification failed unexpectedly: ' + (e?.message ?? e));
  }
  return done();
}
