// Engine vector harness. A vector is { id, description, setup, steps }. Keys come from fixed seeds and the clock is fixed, so every run is
// byte-for-byte reproducible (Ed25519 signatures are deterministic). Each step may carry `expect`; the harness compares it with what the engine
// did. `generate.mjs` fills in `expect` from a run, and the result is reviewed by hand: these are regression vectors for this implementation,
// not an independent check (no second implementation exists yet).
import { isDeepStrictEqual } from 'node:util';
import { createEngine, createMemoryStore, makeSigner, keyPairFromSeed, prepareCommit, prepareReveal, core, DID_UPDATE_TYP, signJws, base58btcEncode as base58 } from '../src/index.mjs';

const seed = (n) => new Uint8Array(32).fill(n);
const HOUR = 3600000;
const clone = (v) => JSON.parse(JSON.stringify(v));
const mb = (signer) => 'z' + base58(signer.publicKey);

export function build(vector) {
  const s = vector.setup;
  let now = Date.parse(s.clock);
  const clock = { now: () => now };
  const engine = createEngine({
    store: createMemoryStore(), clock,
    issuer: makeSigner(keyPairFromSeed(seed(1)).privateKey), logSigner: makeSigner(keyPairFromSeed(seed(2)).privateKey),
  });
  engine.registerTemplate(s.template);
  const people = {};
  for (const [name, p] of Object.entries(s.people)) {
    const priv = keyPairFromSeed(seed(p.seed)).privateKey;
    people[name] = { signer: makeSigner(priv, p.did), priv, secrets: {} };
  }
  return { engine, people, clock, advance: (h) => { now += h * HOUR; }, state: { sealed: null, assessment: s.assessment.id } };
}

const errCode = (fn) => { try { fn(); return null; } catch (e) { return e.code ?? 'internal:' + e.message; } };
const compact = (r) => r && ({ status: r.status, level: r.level, confidence: Math.round(r.confidence * 1e6) / 1e6 });

export function runVector(vector) {
  const ctx = build(vector);
  const { engine, people } = ctx;
  const aid = vector.setup.assessment.id;
  engine.createAssessment(clone(vector.setup.assessment));
  const results = [];
  for (const [i, step] of vector.steps.entries()) {
    let observed;
    const P = people[step.who];
    const view = () => engine.getAssessment(aid);
    switch (step.op) {
      case 'registerDid': {
        const doc = { id: P.signer.did, versions: [{ version: 1, validFrom: step.validFrom, keys: [{ id: '#k1', publicKeyMultibase: mb(P.signer) }], revoked: [] }] };
        engine.registerDid(doc); observed = { registered: P.signer.did }; break;
      }
      case 'rotateDid': {
        // a new key (seed `newSeed`) joins as #k2 and #k1 is revoked from `revokeFrom`; the update is signed with the old key
        const np = makeSigner(keyPairFromSeed(seed(step.newSeed)).privateKey, P.signer.did);
        const version = { version: 2, validFrom: step.validFrom, keys: [{ id: '#k1', publicKeyMultibase: mb(P.signer) }, { id: '#k2', publicKeyMultibase: mb(np) }], revoked: [{ id: '#k1', from: step.revokeFrom }] };
        const jws = P.signer.sign(DID_UPDATE_TYP, { did: P.signer.did, ...version });
        engine.updateDid(P.signer.did, version, jws);
        const kid2 = P.signer.did + '#k2', pk2 = keyPairFromSeed(seed(step.newSeed)).privateKey;
        people[step.newName] = { signer: { did: P.signer.did, kid: kid2, publicKey: np.publicKey, sign: (typ, payload) => signJws({ typ, kid: kid2, payload, privateKey: pk2 }) }, secrets: {} };
        observed = { rotated: P.signer.did }; break;
      }
      case 'invite': {
        const target = people[step.attestor ?? step.who];
        let r; const e = errCode(() => { r = engine.invite(aid, { attestor: step.attestorDid ?? target.signer.did, role: step.role, evidence: step.evidence }); });
        observed = e ? { error: e } : { attestationId: r.attestationId }; break;
      }
      case 'commit': {
        let r, e;
        if (step.copyFrom) { // submit another attestor's commit payload as one's own
          const stored = engine.getAssessment(aid, { view: 'operator' }).commits[step.copyFrom];
          e = errCode(() => { r = engine.commit(aid, { attestationId: step.att, payload: stored.payload, jws: stored.jws }); });
        } else {
          e = errCode(() => {
            const prep = prepareCommit({ signer: P.signer, ticket: step.viaTicket ? engine.ticketFor(aid, step.att) : undefined, assessment: view(), attestationId: step.att, level: step.level, native: step.native, levelMap: vector.setup.template.levelMap, nonce: step.nonce });
            P.secrets[step.att] = prep.secret;
            r = engine.commit(aid, prep.request);
          });
        }
        observed = e ? { error: e } : { committed: r.committed, of: r.of }; break;
      }
      case 'removeInvitation': {
        let r; const e = errCode(() => { r = engine.removeInvitation(aid, step.att); });
        observed = e ? { error: e } : r; break;
      }
      case 'preview': {
        const p = engine.previewRecognition(aid, step.policy ? { policy: step.policy } : {});
        observed = { provisional: p.provisional, policySource: p.policySource, counts: p.counts, recognition: compact(p.recognition), used: p.recognition.used.attestations }; break;
      }
      case 'ticket': {
        const t = engine.ticketFor(aid, step.att);
        observed = { attestor: t.attestor === P?.signer.did ? 'matches' : 'other', evidence: t.evidence, levels: t.levels, levelMap: t.levelMap ?? null, serverDay: t.serverDay, revealOpen: t.revealOpen, templateHash: t.templateHash }; break;
      }
      case 'info': { const i = engine.info(); observed = { time: i.time, today: i.today }; break; }
      case 'advance': ctx.advance(step.hours); observed = { advancedHours: step.hours }; break;
      case 'reveal': {
        let r; let e;
        const req = prepareReveal({ signer: P.signer, assessment: view(), attestationId: step.att, secret: P.secrets[step.att], date: step.date });
        e = errCode(() => { r = engine.reveal(aid, req); });
        observed = e ? { error: e } : { revealed: r.revealed, of: r.of }; break;
      }
      case 'finalize': {
        let doc; const e = errCode(() => { doc = engine.finalize(aid); });
        if (e) { observed = { error: e }; break; }
        ctx.state.sealed = doc;
        const v = engine.verifyCredential(doc);
        observed = { bundleHash: doc.evidence[0].bundleHash, process: doc.sanad.process, checksPass: v.ok, recognition: compact(v.recognition), attestorStats: doc.sanad.bundle.attestors, logSize: doc.sanad.log.checkpoint.payload.size, logRoot: doc.sanad.log.checkpoint.payload.rootHash }; break;
      }
      case 'verify': {
        let doc = clone(ctx.state.sealed);
        if (step.tamper) doc.sanad.bundle = core.applyTamper(doc.sanad.bundle, step.tamper);
        if (step.flipSignatureOf) {
          const a = doc.sanad.bundle.attestations.find((x) => x.id === step.flipSignatureOf);
          const sig = a.signature; a.signature = sig.slice(0, -10) + (sig.at(-10) === 'A' ? 'B' : 'A') + sig.slice(-9);
        }
        const v = engine.verifyCredential(doc, step.policy ? { policy: step.policy } : {});
        observed = { ok: v.ok, failed: v.checks.filter((c) => !c.ok).map((c) => c.name), recognition: compact(v.recognition), dropped: (v.recognition?.dropped ?? []).map((d) => d.id + ':' + d.rule) }; break;
      }
      default: throw new Error('unknown op ' + step.op);
    }
    results.push({ i, op: step.op, observed, ok: step.expect === undefined || isDeepStrictEqual(step.expect, observed) });
  }
  return results;
}
