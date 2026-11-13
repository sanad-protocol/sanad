// Evidence chain, credential sealing, bundle hash, issuer proof and the credential verifier. Format: DESIGN.md section 3.
import { randomUUID } from 'node:crypto';
import { canonical, hashOf, attestationHashOf, attestationPayload, recognise, infer, SANAD_VERSION } from './core.mjs';
import { createResolver, base58btcEncode, DID_LIMITS } from './keys.mjs';
import { templateHash, validatePolicy } from './template.mjs';
import { leafHash, leafBytes, verifyInclusion, verifyCheckpoint } from './log.mjs';
import { verifyWitnesses } from './witness.mjs';
import { statusEntryProblems, checkStatus } from './statuslist.mjs';
import { sittingProblems, missingRequired, checkIdentitySignature, identityRank } from './evidence.mjs';

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
export function buildCredential({ bundle, issuer, template, assessment, process, policy, log, dids = [], now, id, credentialStatus }) {
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
    ...(credentialStatus ? { credentialStatus: clone(credentialStatus) } : {}),
    sanad: { bundle: clone(bundle), template: { id: template.id, hash: template.hash }, assessment, process: clone(process), policy: clone(policy), log: clone(log), dids: clone(dids) },
  };
  const jws = issuer.sign(CREDENTIAL_TYP, clone(doc));
  return { ...doc, proof: { type: 'SanadDetachedJws', verificationMethod: issuer.kid, created: validFrom, jws } };
}

// ---------------------------------------------------------------------------------------------------------------------
// Verification

/** What one verification call will process; larger documents are refused instead of costing unbounded work. */
export const VERIFY_LIMITS = { attestations: 200, evidence: 200, logEntries: 2000, dids: 100, versionsPerHistory: DID_LIMITS.versions, keysPerVersion: DID_LIMITS.keys, revokedPerVersion: DID_LIMITS.revoked };
export const NOTICE = 'Experimental software: the Sanad engine has not been cryptographically reviewed. A passing report records what was signed and logged, not that the attestors were honest. Backdating with a stolen attestor key, collusion and help off camera are not detected.';
const PROCESS_BASE = ['invited', 'committed', 'revealed', 'missing', 'late', 'notCommitted'];
const processOk = (pr) => isObj(pr) && PROCESS_BASE.every((k) => k in pr) && Object.keys(pr).every((k) => PROCESS_BASE.includes(k) || k === 'removed' || k === 'shortfall' || k === 'evidenceAdded')
  && ['removed', 'shortfall', 'evidenceAdded'].every((k) => !(k in pr) || (Array.isArray(pr[k]) && pr[k].every(isStr)));

const POLICY_KEYS = ['minAttestors', 'requireLive', 'halfLifeMonths', 'minAttestorSittings', 'minAgreement', 'maxInferenceDepth', 'inferenceDecay'];

/** Closed member sets everywhere; returns a list of problems (empty when the document has the exact shape). */
function shapeProblems(doc) {
  const p = [];
  const need = (cond, msg) => { if (!cond) p.push(msg); };
  const TOP = ['@context', 'type', 'id', 'issuer', 'validFrom', 'credentialSubject', 'evidence', 'sanad', 'proof'];
  if (!exactly(doc, TOP) && !exactly(doc, [...TOP, 'credentialStatus'])) {
    p.push('top level members must be exactly @context, type, id, issuer, validFrom, credentialSubject, evidence, sanad, proof, and optionally credentialStatus');
    return p;
  }
  if ('credentialStatus' in doc) p.push(...statusEntryProblems(doc.credentialStatus));
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
  need(processOk(s.process), 'sanad.process members');
  need(exactly(s.policy, ['id', ...POLICY_KEYS]), 'sanad.policy members');
  need(Array.isArray(s.dids) && s.dids.every((d) => exactly(d, ['id', 'versions']) && isStr(d.id) && Array.isArray(d.versions)), 'sanad.dids must be a list of { id, versions }');
  if (Array.isArray(s.dids)) {
    if (s.dids.length > VERIFY_LIMITS.dids) p.push('too many DID histories (limit ' + VERIFY_LIMITS.dids + ')');
    for (const d of s.dids) {
      if (!isObj(d) || !Array.isArray(d.versions)) continue;
      if (d.versions.length > VERIFY_LIMITS.versionsPerHistory) { p.push(`DID history ${String(d.id).slice(0, 60)} has more than ${VERIFY_LIMITS.versionsPerHistory} versions`); continue; }
      for (const v of d.versions) if (isObj(v) && ((Array.isArray(v.keys) && v.keys.length > VERIFY_LIMITS.keysPerVersion) || (Array.isArray(v.revoked) && v.revoked.length > VERIFY_LIMITS.revokedPerVersion))) { p.push(`a DID version has more than ${VERIFY_LIMITS.keysPerVersion} keys or ${VERIFY_LIMITS.revokedPerVersion} revocations`); break; }
    }
  }
  if (isObj(s.log) && Array.isArray(s.log.entries) && s.log.entries.length > VERIFY_LIMITS.logEntries) { p.push('too many log entries (limit ' + VERIFY_LIMITS.logEntries + ')'); return p; }
  const l = s.log;
  need(exactly(l, ['logId', 'logKey', 'entries', 'proofs', 'checkpoint']) && Array.isArray(l.entries) && Array.isArray(l.proofs)
    && l.entries.every((e) => exactly(e, ['index', 'leaf'])) && l.proofs.every((e) => exactly(e, ['index', 'size', 'proof'])) && exactly(l.checkpoint, ['payload', 'jws']), 'sanad.log members');
  const b = s.bundle;
  if (isObj(b) && ((Array.isArray(b.attestations) && b.attestations.length > VERIFY_LIMITS.attestations) || (Array.isArray(b.evidence) && b.evidence.length > VERIFY_LIMITS.evidence))) { p.push('too many evidence items or attestations (limits ' + VERIFY_LIMITS.evidence + ' and ' + VERIFY_LIMITS.attestations + ')'); return p; }
  if (!exactly(b, ['skill', 'claimedLevel', 'subject', 'evidence', 'attestations', 'attestors'])) { p.push('bundle members must be exactly skill, claimedLevel, subject, evidence, attestations, attestors'); return p; }
  need(isStr(b.skill) && isStr(b.subject) && Number.isInteger(b.claimedLevel) && b.claimedLevel >= 0 && b.claimedLevel <= 5, 'bundle skill, subject and claimedLevel (an integer from 0 to 5)');
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

/**
 * A resolver for verification. Keys come from, in order: the verifier's own resolver, the DID histories the verifier supplies (trustedDidHistories),
 * and only then the histories embedded in the credential. An embedded history is the issuer's own claim about a did:web identity: using it is
 * recorded in `usedEmbedded` so that the caller can require the verifier to have pinned the key.
 */
function verifierResolver(given, embeddedDids, trusted) {
  const mapOf = (list) => { const m = new Map(); for (const d of Array.isArray(list) ? list : []) if (isObj(d) && isStr(d.id)) m.set(d.id, d); return m; };
  const embMap = mapOf(embeddedDids), trMap = mapOf(trusted);
  const emb = createResolver({ store: { get: (c, id) => embMap.get(id) ?? null, put() {} } });
  const tr = createResolver({ store: { get: (c, id) => trMap.get(id) ?? null, put() {} } });
  const usedEmbedded = new Map(); // did -> Set of multibase keys that verified a statement
  const givenHas = new Map();     // decided once per DID (a resolver's get() copies its record)
  const has = (did) => { if (!givenHas.has(did)) { let h = false; try { h = !!(given && typeof given.get === 'function' && isStr(did) && !did.startsWith(DID_KEY) && given.get(did)); } catch { h = false; } givenHas.set(did, h); } return givenHas.get(did); };
  const pick = (did) => (has(did) ? { r: given, emb: false } : trMap.has(did) ? { r: tr, emb: false } : { r: emb, emb: true });
  return {
    usedEmbedded,
    keysAt(did, date) { try { return pick(did).r.keysAt(did, date); } catch { return []; } },
    verifyStatement(arg) {
      try {
        const { r, emb: isEmb } = pick(arg.signer);
        const res = r.verifyStatement(arg);
        if (res.ok && isEmb && !String(arg.signer).startsWith(DID_KEY)) {
          const mb = res.publicKey ? 'z' + base58btcEncode(res.publicKey) : '?';
          if (!usedEmbedded.has(arg.signer)) usedEmbedded.set(arg.signer, new Set());
          usedEmbedded.get(arg.signer).add(mb);
        }
        return res;
      } catch { return { ok: false, reason: 'bad_did_history' }; }
    },
  };
}

const ADD = (checks, name, ok, detail) => checks.push({ name, ok, detail });
const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);

/**
 * Verifies a credential document. Never throws. The verifier decides everything that is a judgement:
 *  - `policy` (all seven fields) and the evaluation day (`policy.asOf`, `asOf`, or `useVerifierClock` with `now`); `useRecommendedPolicy: true` is an explicit, labelled opt-in to the issuer's recommendation;
 *  - whom to trust: `trustedIssuers`, `trustedLogKeys` (DIDs), `trustedLogIds`, and for did:web identities `pinnedKeys` ({ did: [multibase keys] }) or `trustedDidHistories`;
 *    unpinned issuer or log key makes `ok` false unless `allowUnpinned: true`; an embedded did:web history is untrusted unless its key is pinned (`allowEmbeddedDids: true` overrides, insecurely);
 *  - attestor statistics: `attestorStats` (the verifier's own) replace the issuer's; issuer-supplied statistics used for a threshold make `ok` false unless `allowIssuerStatistics: true`;
 *  - `allowedAttestors` (an allow-list) and `template` (checked against the credential's template hash, roles and evidence kinds).
 * @param {unknown} doc
 * @param {object} [opts]
 */
export function verifyCredential(doc, opts = {}) {
  const checks = [], warnings = [];
  let recognition = null, inferred = [], basis = null, unverifiedLabel = false;
  // when a check failed the recognition is what the data would give if it were genuine: it is labelled, not withheld
  const done = () => { const ok = checks.every((c) => c.ok); return { ok, checks, recognition: recognition && !ok && unverifiedLabel ? { ...recognition, unverified: true } : recognition, inferred, warnings, basis, notice: NOTICE }; };
  try {
    if (!isObj(doc)) { ADD(checks, 'shape', false, 'the credential must be a JSON object'); return done(); }
    const problems = shapeProblems(doc);
    ADD(checks, 'shape', problems.length === 0, problems.length ? problems.join('; ') : 'closed member sets everywhere; no unknown members');
    if (problems.length) return done();

    const { sanad } = doc, bundle = sanad.bundle;
    const resolver = verifierResolver(opts.resolver, sanad.dids, opts.trustedDidHistories);
    const day = new Date(doc.validFrom).toISOString().slice(0, 10);

    // issuer proof
    {
      const { proof } = doc, { proof: _omit, ...body } = doc;
      const r = proof.type === 'SanadDetachedJws' ? resolver.verifyStatement({ jws: proof.jws, payload: body, typ: CREDENTIAL_TYP, signer: doc.issuer, date: day }) : { ok: false, reason: 'unknown_proof_type' };
      const kidOk = r.ok && r.kid === proof.verificationMethod;
      const proofOk = r.ok && kidOk && proof.created === doc.validFrom;
      ADD(checks, 'issuer-proof', proofOk,
        r.ok ? (kidOk ? (proof.created === doc.validFrom ? `signed by ${r.kid}, valid on ${day}` : 'proof.created differs from validFrom') : 'verificationMethod differs from the signing key') : 'issuer signature refused: ' + r.reason);
      // an unsigned or forged document is not examined further, unless the caller asks for the diagnosis (`diagnose: true`)
      if (!proofOk && opts.diagnose !== true) { warnings.push('verification stopped at the failed issuer proof; pass diagnose to examine the rest'); return done(); }
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

    // sitting evidence: the members of SPEC 3.3 that are present are well formed; the identity statement is signed; the template's demands are met
    {
      const sittings = bundle.evidence.filter((e) => e.kind === 'sitting');
      if (sittings.length) {
        const why = [], soft = [];
        const hasShortfall = Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length > 0;
        for (const e of sittings) {
          const sp = sittingProblems(e.body);
          if (sp.length) { why.push(`${e.id}: ${sp.join(', ')}`); continue; }
          if ('identityAssurance' in e.body) { const ck = checkIdentitySignature(e.body, resolver); if (!ck.ok) why.push(`${e.id}: identity statement refused (${ck.reason})`); }
          if (opts.minIdentityLevel !== undefined) {
            const need = identityRank(opts.minIdentityLevel);
            if (need < 0) why.push('minIdentityLevel must be A0, A1 or A2');
            else if (identityRank(e.body.identityAssurance?.level) < need) why.push(`${e.id}: identity assurance ${e.body.identityAssurance?.level ?? 'absent'} is below the required ${opts.minIdentityLevel}`);
          }
          if (opts.template !== undefined) {
            const item = opts.template?.evidence?.find((x) => sanad.assessment + '.' + x.key === e.id);
            const miss = missingRequired(e.body, item);
            if (miss.length && !hasShortfall) why.push(`${e.id}: the template requires ${miss.join(', ')} and it is missing`);
          }
          const absent = ['paperFingerprint', 'strokeLogHead', 'recordingSha256'].filter((k) => !(k in e.body));
          if (absent.length) soft.push(`${e.id} carries no ${absent.join(', ')}`);
        }
        for (const m of soft) warnings.push('sitting evidence: ' + m + ' (the hash binds nothing about the sitting until it is present)');
        ADD(checks, 'sitting-evidence', why.length === 0, why.length ? why.join('; ') : `${sittings.length} sitting evidence item(s): members well formed, identity statements verify`);
      }
    }

    // ids belong to this assessment
    {
      const pre = sanad.assessment + '.';
      const bad = [...bundle.evidence.map((e) => e.id), ...bundle.attestations.map((a) => a.id)].filter((id) => !id.startsWith(pre));
      ADD(checks, 'ids', bad.length === 0, bad.length ? `ids outside assessment ${sanad.assessment}: ${bad.slice(0, 5).join(', ')}` : 'every evidence and attestation id belongs to assessment ' + sanad.assessment);
    }

    // attestor signatures
    const sigCache = new Map(); // each attestor signature is verified once and the result is shared
    const sigReason = (a) => {
      if (sigCache.has(a.id)) return sigCache.get(a.id);
      const { prev: _p, ...stmt } = attestationPayload(a);
      const r = resolver.verifyStatement({ jws: a.signature, payload: stmt, typ: ATTESTATION_TYP, signer: a.attestor, date: a.date });
      sigCache.set(a.id, r); return r;
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
      if (Array.isArray(opts.trustedLogIds) && !opts.trustedLogIds.includes(l.logId)) why.push('log id ' + l.logId + ' is not among the trusted log ids');
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
      ADD(checks, 'log', why.length === 0, why.length ? why.join('; ') : `${l.entries.length} embedded entr${l.entries.length === 1 ? 'y' : 'ies'} verified against the checkpoint of size ${cp.payload.size}; every attestation hash and the bundle hash are leaves`);
    }

    // witnesses: independent parties that cosigned a checkpoint consistent with this credential's (SPEC 8.2)
    if (opts.requireWitnesses !== undefined) {
      const n = opts.requireWitnesses;
      if (!Number.isInteger(n) || n < 0) ADD(checks, 'witnesses', false, 'requireWitnesses must be a non-negative integer');
      else if (n > 0) {
        const ev = isObj(opts.witnessEvidence) ? opts.witnessEvidence : {};
        const w = verifyWitnesses({ checkpoint: sanad.log.checkpoint, logKey: sanad.log.logKey, resolver, cosigned: ev.cosigned, consistency: ev.consistency, trusted: opts.trustedWitnesses });
        ADD(checks, 'witnesses', w.count >= n, w.count >= n ? `${w.count} pinned witness(es) cosigned a checkpoint consistent with the credential's: ${w.witnesses.join(', ')}` : `${w.count} of the required ${n} pinned witnesses: ${w.problems.join('; ') || 'none supplied'}`);
      }
    }

    // revocation: the Bitstring Status List the credential names (SPEC 8.3)
    if (doc.credentialStatus !== undefined) {
      if (Array.isArray(opts.statusLists)) {
        const r = checkStatus({ credential: doc, lists: opts.statusLists, now: opts.now ?? Date.now(), resolver });
        ADD(checks, 'revocation', r.ok, r.detail);
      } else if (opts.requireStatus === true) ADD(checks, 'revocation', false, 'the credential names a status list (' + doc.credentialStatus.statusListCredential + ') and none was supplied (requireStatus)');
      else warnings.push('revocation not checked: the credential names the status list ' + doc.credentialStatus.statusListCredential + '; supply it (statusLists) to learn whether it was revoked');
    }

    // pins: keys are what is trusted; DIDs are names the verifier chose
    const pin = (name, label, list, value) => {
      if (Array.isArray(list)) { const ok = list.includes(value); ADD(checks, name, ok, ok ? `${label} is pinned: ${value}` : `${label} ${value} is not among the pinned ${label}s`); }
      else if (opts.allowUnpinned === true) { ADD(checks, name, true, `${label} not pinned (allowUnpinned): ${value}`); warnings.push(`${label} not pinned`); }
      else ADD(checks, name, false, `${label} ${value} is not pinned: pass ${name === 'trusted-issuer' ? 'trustedIssuers' : 'trustedLogKeys'}, or allowUnpinned to accept any`);
    };
    pin('trusted-issuer', 'issuer', opts.trustedIssuers, doc.issuer);
    pin('trusted-log-key', 'log key', opts.trustedLogKeys, sanad.log.logKey);

    // embedded DID histories are the issuer's own claim about a did:web key
    if (resolver.usedEmbedded.size) {
      const pinned = isObj(opts.pinnedKeys) ? opts.pinnedKeys : {};
      const bad = [];
      for (const [did, keys] of resolver.usedEmbedded) for (const k of keys) if (!(Array.isArray(pinned[did]) && pinned[did].includes(k))) bad.push(`${did} (key ${k.slice(0, 12)}...)`);
      if (bad.length && opts.allowEmbeddedDids === true) { warnings.push('DID histories embedded in the credential were trusted (allowEmbeddedDids): ' + bad.join(', ')); ADD(checks, 'did-histories', true, 'embedded did histories accepted without pinned keys (allowEmbeddedDids)'); }
      else {
        if (bad.length) warnings.push('embedded DID histories are the issuer\'s own claim; pin the keys (pinnedKeys) or supply the histories (trustedDidHistories): ' + bad.join(', '));
        ADD(checks, 'did-histories', bad.length === 0, bad.length ? 'keys known only from histories embedded in the credential and not pinned by the verifier: ' + bad.join(', ') : 'every did:web key used is pinned by the verifier');
      }
    }

    // the process record agrees with the bundle
    {
      const pr = sanad.process, n = bundle.attestations.length, why = [];
      if (pr.revealed !== n) why.push(`process.revealed is ${pr.revealed} but the bundle has ${n} attestation(s)`);
      if (pr.committed < pr.revealed || pr.committed > pr.invited) why.push('process counts are inconsistent (revealed <= committed <= invited must hold)');
      if (pr.missing.length !== pr.committed - pr.revealed) why.push('process.missing does not account for committed minus revealed');
      if (pr.notCommitted.length !== pr.invited - pr.committed) why.push('process.notCommitted does not account for invited minus committed');
      if (pr.late.some((id) => !pr.missing.includes(id))) why.push('process.late names an attestation that is not missing');
      const have = new Set(bundle.attestations.map((a) => a.id));
      if (pr.missing.some((id) => have.has(id))) why.push('process.missing names an attestation that is in the bundle');
      ADD(checks, 'process', why.length === 0, why.length ? why.join('; ') : 'process counts agree with the bundle');
    }

    // template (when the verifier supplies it)
    if (opts.template !== undefined) {
      const why = [];
      try {
        const t = opts.template;
        if (templateHash(t) !== sanad.template.hash) why.push('the supplied template does not have the credential\'s template hash');
        if (t.id !== sanad.template.id) why.push('template id differs');
        const roles = t.attestors?.roles ?? [];
        for (const a of bundle.attestations) if (!roles.includes(a.role)) why.push(`attestation ${a.id} has role "${a.role}", which the template does not list`);
        const kinds = new Map((t.evidence ?? []).map((e) => [sanad.assessment + '.' + e.key, e.kind]));
        for (const e of bundle.evidence) if (kinds.get(e.id) !== e.kind) why.push(`evidence ${e.id} is not an item of kind ${e.kind} of the template`);
        const have = new Set(bundle.evidence.map((e) => e.id));
        for (const id of kinds.keys()) if (!have.has(id)) why.push(`the template's evidence item ${id} is missing from the credential`);
        // the template minimum, as the engine enforces it at finalize: conflicted attestors do not count
        const short = [];
        const per = new Map(bundle.evidence.map((e) => [e.id, new Set()]));
        for (const a of bundle.attestations) if (!a.conflictDeclared) per.get(a.evidence)?.add(a.attestor);
        for (const e of bundle.evidence) if (e.kind !== 'auto' && per.get(e.id).size < (t.attestors?.min ?? 1)) short.push(e.id);
        if (t.liveSitting && !bundle.evidence.some((e) => e.kind === 'sitting' && per.get(e.id).size > 0)) short.push('liveSitting');
        if (short.length && !(Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length)) why.push('below the template minimum (' + short.join(', ') + ') and the credential records no process.shortfall');
      } catch { why.push('the supplied template is not usable'); }
      ADD(checks, 'template', why.length === 0, why.length ? why.join('; ') : 'template hash, roles and evidence kinds match');
    } else warnings.push('template not supplied: roles and evidence kinds were not checked against it');
    if (Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length) warnings.push('the operator finalized below the template minimum: ' + sanad.process.shortfall.join('; '));

    // the verifier's policy and evaluation day
    let pol = null, polSource = null, asOfSource = null;
    if (opts.policy !== undefined) { pol = isObj(opts.policy) ? { ...opts.policy } : opts.policy; polSource = 'verifier'; }
    else if (opts.useRecommendedPolicy === true) { pol = { ...sanad.policy }; delete pol.id; polSource = 'issuer-recommendation'; }
    if (isObj(pol)) {
      if (pol.asOf !== undefined) asOfSource = 'policy';
      else if (opts.asOf !== undefined) { pol.asOf = opts.asOf; asOfSource = 'option'; }
      else if (opts.useVerifierClock === true) { pol.asOf = isoDay(opts.now ?? Date.now()); asOfSource = 'verifier-clock'; }
      else if (polSource === 'issuer-recommendation') { pol.asOf = day; asOfSource = 'credential-date'; }
    }
    if (pol === null) ADD(checks, 'policy', false, 'no verifier policy supplied: pass policy (all seven fields and asOf), or useRecommendedPolicy to take the issuer\'s recommendation knowingly');
    else {
      const pp = validatePolicy(pol);
      ADD(checks, 'policy', pp.length === 0, pp.length ? 'policy refused: ' + pp.join('; ') : `${polSource} policy; evaluation day ${pol.asOf} (${asOfSource})`);
      if (pp.length === 0) {
        basis = { policySource: polSource === 'verifier' ? 'verifier' : 'issuer-recommendation', asOfSource };
        // statistics
        const own = opts.attestorStats;
        if (own !== undefined) {
          const okShape = isObj(own) && Object.values(own).every((st) => isObj(st) && Number.isFinite(st.sittings) && Number.isFinite(st.agreement));
          ADD(checks, 'attestor-statistics', okShape, okShape ? 'verifier-supplied statistics replace the issuer\'s' : 'attestorStats must map DIDs to { sittings, agreement }');
        } else if (pol.minAttestorSittings > 0 || pol.minAgreement > 0) {
          const allow = opts.allowIssuerStatistics === true;
          ADD(checks, 'attestor-statistics', allow, allow ? 'issuer-supplied statistics used for a threshold (allowIssuerStatistics)' : 'the policy has a statistics threshold but the only statistics are the issuer\'s, which no verifier can recompute from the log: pass attestorStats, or allowIssuerStatistics');
          if (allow) warnings.push('issuer-supplied statistics used for a threshold; they are not recomputable from the hash-only log');
        }
        try {
          const cred = isObj(own) ? { ...bundle, attestors: own } : bundle;
          const ropts = { verifySignature: (a) => sigReason(a).ok };
          if (Array.isArray(opts.allowedAttestors)) ropts.allowAttestor = (d) => opts.allowedAttestors.includes(d);
          recognition = recognise(cred, pol, ropts);
          unverifiedLabel = true;
          if (opts.graph && recognition.status !== 'not-recognised') inferred = infer(opts.graph, bundle.skill, recognition.level, recognition.confidence, pol, [bundle.skill]);
        } catch (e) { ADD(checks, 'recognition', false, 'the recognition function refused the input: ' + (e?.message ?? e)); }
      }
    }
  } catch (e) {
    ADD(checks, 'internal', false, 'verification failed unexpectedly: ' + (e?.message ?? e));
  }
  return done();
}
