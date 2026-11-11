// A toy host platform ("a course site") that plugs Sanad in by vendoring the single-file bundle (integration mode 1).
// The host keeps its own people and grades; the engine knows only pseudonymous subject ids, DIDs and hashes.
// DEMONSTRATION: attestor keys are generated here so that one script can play the examiners. In a real host each examiner signs in their own client.
import { createEngine, createMemoryStore, makeSigner, generateKeyPair, prepareCommit, prepareReveal, verifyConsistency, verifyCredential } from '../dist/sanad-engine.mjs';
import { randomUUID } from 'node:crypto';

/** Host grades run 1..6; Sanad levels run 0..5. This mapping is the host's choice and lives in the host (and in the template's levelMap). */
export const gradeToLevel = (grade) => { if (!Number.isInteger(grade) || grade < 1 || grade > 6) throw new Error('grade 1..6'); return grade - 1; };
export const levelToGrade = (level) => level + 1;

export function createToyHost({ template, now = () => Date.now() } = {}) {
  const clock = { now };
  const issuer = makeSigner(generateKeyPair().privateKey), logSigner = makeSigner(generateKeyPair().privateKey);
  const engine = createEngine({ store: createMemoryStore(), issuer, logSigner, clock });
  engine.registerTemplate(template);
  const host = {
    engine, issuer, logSigner,
    people: new Map(),      // host id -> { name, pseudonym }: personal data stays here
    checkpoints: [],        // what the host must keep: every checkpoint it has seen
    pinned: { issuer: issuer.did, logKey: logSigner.did },
    enrol(hostId, name) { const pseudonym = 'urn:uuid:' + randomUUID(); host.people.set(hostId, { name, pseudonym }); return pseudonym; },
    keepCheckpoint() {
      const cp = engine.log.checkpoint();
      const last = host.checkpoints.at(-1);
      if (last) { // the log must only have grown: a consistency proof from the kept checkpoint to the new one
        const c = engine.log.consistency(last.payload.size, cp.payload.size);
        if (!verifyConsistency({ m: c.m, n: c.n, proof: c.proof, rootM: last.payload.rootHash, rootN: cp.payload.rootHash })) throw new Error('log history was rewritten');
      }
      host.checkpoints.push(cp); return cp;
    },
    /** Runs one sitting with the given examiner levels (host grades) and returns the credential. */
    sit({ hostId, claimedGrade, examiners, date }) {
      const subject = host.people.get(hostId).pseudonym;
      const a = engine.createAssessment({ templateId: template.id, subject, claimedLevel: gradeToLevel(claimedGrade), evidence: [{ key: 'E1', date, summary: 'Oral sitting', body: { minutes: 40 } }] });
      const sitters = examiners.map((e) => ({ ...e, key: generateKeyPair() })).map((e) => ({ ...e, signer: makeSigner(e.key.privateKey) }));
      const invs = sitters.map((s) => engine.invite(a.id, { attestor: s.signer.did, role: template.attestors.roles[0], evidence: 'E1' }));
      const secrets = sitters.map((s, i) => {
        const { request, secret } = prepareCommit({ signer: s.signer, assessment: engine.getAssessment(a.id), attestationId: invs[i].attestationId, level: gradeToLevel(s.grade) });
        engine.commit(a.id, request); return secret;
      });
      sitters.forEach((s, i) => engine.reveal(a.id, prepareReveal({ signer: s.signer, assessment: engine.getAssessment(a.id), attestationId: invs[i].attestationId, secret: secrets[i], date })));
      const credential = engine.finalize(a.id);
      host.keepCheckpoint();
      return credential;
    },
  };
  return host;
}

/** Verify-only mode (3): a third party with the vendored bundle, the issuer and log keys it has chosen to trust, and its own policy. */
export function thirdPartyCheck(credential, { issuer, logKey, policy }) {
  return verifyCredential(credential, { trustedIssuers: [issuer], trustedLogKeys: [logKey], policy });
}
