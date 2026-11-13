// Reproductions of the findings of the second independent review (each failed before its fix).
import { describe, it, expect } from 'vitest';
import * as H from './helpers.mjs';
import { verifyCredential, generateKeyPair, base58btcEncode, signJws, jwsHeader, b64u, createResolver, makeSigner, keyPairFromSeed, validateTemplate, DID_LIMITS, VERIFY_LIMITS } from '../src/index.mjs';
import { runExample } from '../examples/run.mjs';
import { main } from '../src/cli.mjs';

const POL = { minAttestors: 2, requireLive: true, halfLifeMonths: 36, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 2, inferenceDecay: 0.8, asOf: '2026-03-03' };
const clone = (v) => JSON.parse(JSON.stringify(v));
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);
const seed = (n) => new Uint8Array(32).fill(n);

describe('H1: bounded work in verification', () => {
  function dosCredential(nKeys, nAtt, versions = 1) {
    const c = clone(runExample('maths-oral').credential);
    const did = 'did:web:evil.example';
    const keys = []; for (let i = 0; i < nKeys; i++) keys.push({ id: '#k' + i, publicKeyMultibase: 'z' + base58btcEncode(generateKeyPair().publicKey) });
    c.sanad.dids = [{ id: did, versions: Array.from({ length: versions }, (_, v) => ({ version: v + 1, validFrom: `20${10 + v}-01-01`, keys, revoked: [] })) }];
    const hdr = b64u(new TextEncoder().encode(jwsHeader('sanad-attestation+jws', did + '#k0'))); const fake = hdr + '..' + b64u(new Uint8Array(64).fill(1));
    const a0 = c.sanad.bundle.attestations[0];
    c.sanad.bundle.attestations = Array.from({ length: nAtt }, (_, i) => ({ ...a0, id: c.sanad.assessment + '.a' + String(i).padStart(3, '0'), attestor: did, signature: fake }));
    c.issuer = did;
    return c;
  }
  it('limits are small normative numbers', () => { expect(DID_LIMITS).toEqual({ versions: 16, keys: 8, revoked: 16 }); expect(VERIFY_LIMITS.keysPerVersion).toBe(8); });
  it('a history with 1500 keys is refused by the shape check in well under 100 ms', () => {
    const c = dosCredential(1500, 5);
    const t = performance.now(); const r = verifyCredential(c, { policy: POL, allowUnpinned: true }); const ms = performance.now() - t;
    expect(r.ok).toBe(false); expect(failed(r)).toEqual(['shape']); expect(r.checks[0].detail).toMatch(/keys/);
    expect(ms).toBeLessThan(100);
  });
  it('a history of 17 versions is refused', () => { expect(failed(verifyCredential(dosCredential(2, 2, 17), { policy: POL, allowUnpinned: true }))).toEqual(['shape']); });
  it('the maximum allowed (16 versions x 8 keys, 200 forged attestations) is processed in well under 100 ms and stops at the failed issuer proof', () => {
    const c = dosCredential(8, 200, 16);
    const t = performance.now(); const r = verifyCredential(c, { policy: POL, allowUnpinned: true }); const ms = performance.now() - t;
    expect(r.ok).toBe(false); expect(failed(r)).toContain('issuer-proof'); expect(r.warnings.join(' ')).toMatch(/stopped at the failed issuer proof/);
    expect(ms).toBeLessThan(100);
    expect(r.recognition).toBeNull();
    const t2 = performance.now(); const d = verifyCredential(c, { policy: POL, allowUnpinned: true, diagnose: true }); const ms2 = performance.now() - t2;
    expect(failed(d)).toContain('attestor-signatures'); expect(ms2).toBeLessThan(100);
  });
  it('registration enforces the same limits', () => {
    const { engine } = H.setup();
    const keys = Array.from({ length: 9 }, (_, i) => ({ id: '#k' + i, publicKeyMultibase: 'z' + base58btcEncode(generateKeyPair().publicKey) }));
    H.code(() => engine.registerDid({ id: 'did:web:big.example', versions: [{ version: 1, validFrom: '2026-01-01', keys, revoked: [] }] }), 'bad_did_document');
  });
});

describe('unverified label', () => {
  it('a recognition next to a failed check says it is unverified', () => {
    const r = runExample('maths-oral'); const bad = clone(r.credential); bad.sanad.bundle.attestations[0].level = 5;
    const rep = r.engine.verifyCredential(bad, { policy: POL, diagnose: true });
    expect(rep.ok).toBe(false); expect(rep.recognition.unverified).toBe(true);
    expect(r.engine.verifyCredential(r.credential, { policy: POL }).recognition.unverified).toBeUndefined();
  });
});

describe('M5: the verifier checks the template minimum, completeness and the process record', () => {
  it('below the minimum without a recorded shortfall fails with the template; with the shortfall it passes with a warning', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const sec = H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 4).secret;
    s.engine.closeInvitations('as-1');
    H.revealAs(s.engine, s.people.A, 'as-1', sec);
    s.clock.advance(1000);
    const doc = s.engine.finalize('as-1', { allowShortfall: true });
    expect(verifyCredential(doc, { policy: POL, trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did], template: s.tpl }).ok).toBe(true);
    const stripped = clone(doc); delete stripped.sanad.process.shortfall;
    const r = verifyCredential(stripped, { policy: POL, trustedIssuers: [s.issuer.did], trustedLogKeys: [s.logSigner.did], template: s.tpl, diagnose: true });
    expect(failed(r)).toContain('template');
  });
  it('a declared conflict does not count toward the minimum at finalize', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 3).secret);
    H.revealAs(s.engine, s.people.A, 'as-1', sec[0]); H.revealAs(s.engine, s.people.B, 'as-1', sec[1], '2026-03-01', true);
    H.code(() => s.engine.finalize('as-1'), 'below_template_minimum');
  });
  it('a process record that disagrees with the bundle fails', () => {
    const r = runExample('maths-oral'); const bad = clone(r.credential); bad.sanad.process.revealed = 1;
    expect(failed(r.engine.verifyCredential(bad, { policy: POL, diagnose: true }))).toContain('process');
    expect(r.engine.verifyCredential(r.credential, { policy: POL }).checks.find((c) => c.name === 'process').ok).toBe(true);
  });
  it('an evidence item of the template that is missing from the credential fails', () => {
    const s = H.setup({ tpl: H.template({ evidence: [{ key: 'E1', kind: 'sitting', summary: 's' }, { key: 'E2', kind: 'artifact', summary: 'a' }] }) });
    const r = s.engine.verifyCredential({}, {}); void r;
    const ex = runExample('code-portfolio'); const bad = clone(ex.credential);
    bad.sanad.bundle.evidence = bad.sanad.bundle.evidence.filter((e) => !e.id.endsWith('.E2')); bad.sanad.bundle.attestations = bad.sanad.bundle.attestations.filter((a) => !a.evidence.endsWith('.E2'));
    expect(failed(ex.engine.verifyCredential(bad, { policy: POL, diagnose: true }))).toContain('template');
  });
});

describe('M6: subjects are strict UUID URNs or opaque hashes', () => {
  it('accepts urn:uuid and urn:sanad:subject:<hex> only', () => {
    const { engine } = H.setup();
    for (const subject of ['urn:uuid:ada', 'urn:uuid:1', 'urn:isbn:0451450523', 'urn:ada:lovelace', 'urn:uuid:11111111-1111-4111-8111-11111111111g', 'urn:sanad:subject:XYZ', 'urn:sanad:subject:abc']) H.code(() => H.newAssessment(engine, { id: 's' + Math.random().toString(16).slice(2, 8), subject }), 'bad_subject');
    expect(H.newAssessment(engine, { id: 'ok1', subject: 'urn:uuid:11111111-1111-4111-8111-111111111111' }).id).toBe('ok1');
    expect(H.newAssessment(engine, { id: 'ok2', subject: 'urn:sanad:subject:' + 'ab'.repeat(32) }).id).toBe('ok2');
  });
});

describe('M9: claimedLevel is range-checked', () => {
  it('the shape check refuses a claimedLevel outside 0..5', () => {
    const r = runExample('maths-oral');
    for (const v of [9, -1, 2.5]) { const bad = clone(r.credential); bad.sanad.bundle.claimedLevel = v; bad.credentialSubject.claimedLevel = v; expect(failed(r.engine.verifyCredential(bad, { policy: POL }))).toEqual(['shape']); }
  });
});

describe('M10: the reveal phase waits for the roster', () => {
  const mk = () => { const s = H.setup(); H.newAssessment(s.engine); return s; };
  it('does not open while fewer than attestors.min are invited, even if everyone invited has committed', () => {
    const s = mk(); const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const a = H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 4).secret;
    expect(s.engine.getAssessment('as-1').revealOpen).toBe(false);
    H.code(() => H.revealAs(s.engine, s.people.A, 'as-1', a), 'reveal_not_open');
    const j = s.engine.invite('as-1', { attestor: s.people.B.did, role: 'examiner', evidence: 'E1' }); // still possible: nothing is open
    expect(j.attestationId).toBe('as-1.a02');
    H.commitAs(s.engine, s.people.B, 'as-1', j.attestationId, 3);
    expect(s.engine.getAssessment('as-1').revealOpen).toBe(true);
  });
  it('the operator can close invitations explicitly, which also stops further invitations', () => {
    const s = mk(); const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const a = H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 4).secret;
    expect(s.engine.closeInvitations('as-1')).toEqual({ closed: true, invited: 1 });
    expect(s.engine.getAssessment('as-1').revealOpen).toBe(true);
    H.code(() => s.engine.invite('as-1', { attestor: s.people.B.did, role: 'examiner', evidence: 'E1' }), 'state');
    expect(H.revealAs(s.engine, s.people.A, 'as-1', a).revealed).toBe(1);
  });
  it('the commit deadline still opens the reveal phase', () => {
    const s = mk(); const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const a = H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 4).secret; s.clock.advance(25 * H.HOUR);
    expect(H.revealAs(s.engine, s.people.A, 'as-1', a, '2026-03-02').revealed).toBe(1);
  });
});

describe('M4: log and engine times come from one monotonic clock', () => {
  it('log entry and checkpoint timestamps never go backwards when the clock does', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    s.clock.advance(3 * H.HOUR); H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 3);
    s.clock.advance(-8 * H.HOUR);
    const j = s.engine.invite('as-1', { attestor: s.people.B.did, role: 'examiner', evidence: 'E1' }); H.commitAs(s.engine, s.people.B, 'as-1', j.attestationId, 3);
    const ts = s.engine.log.entries().map((e) => JSON.parse(e.leaf).ts);
    expect([...ts].sort()).toEqual(ts);
    expect(Date.parse(s.engine.log.checkpoint().payload.timestamp)).toBeGreaterThanOrEqual(Date.parse(ts.at(-1)));
  });
  it('the docs do not claim that log time defends against a stolen key', async () => {
    const { readFileSync } = await import('node:fs'); const { fileURLToPath } = await import('node:url');
    for (const f of ['../DESIGN.md', '../README.md', '../../content/en/engine.md']) expect(readFileSync(fileURLToPath(new URL(f, import.meta.url)), 'utf8'), f).not.toMatch(/log time of the commit is the defence|verifier report shows it/);
  });
});

describe('lows', () => {
  it('a template evidence key that looks like an attestation id is refused', () => {
    const t = H.template({ evidence: [{ key: 'a01', kind: 'sitting', summary: 's' }] });
    expect(validateTemplate(t).ok).toBe(false);
  });
  it('commit is idempotent after a crash between the log append and the save', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const i = s.engine.invite('as-1', { attestor: s.people.A.did, role: 'examiner', evidence: 'E1' });
    const realPut = s.store.put.bind(s.store); let boom = true;
    s.store.put = (c, id, v) => { if (boom && c === 'assessments' && Object.keys(v.commits).length) { boom = false; throw new Error('disk full'); } return realPut(c, id, v); };
    expect(() => H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 3, 'q'.repeat(22))).toThrow(/disk full/);
    const n = s.engine.log.size();
    expect(H.commitAs(s.engine, s.people.A, 'as-1', i.attestationId, 3, 'q'.repeat(22)).result.committed).toBe(1);
    expect(s.engine.log.size()).toBe(n);
  });
  it('the CLI refuses to verify without a policy unless told to use the recommendation', async () => {
    const out = [], err = [];
    const r = runExample('maths-oral'); const { writeFileSync, mkdtempSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
    const f = join(mkdtempSync(join(tmpdir(), 'v-')), 'c.json'); writeFileSync(f, JSON.stringify(r.credential));
    const run = (...a) => main(['verify', f, ...a], { out: (x) => out.push(x), err: (x) => err.push(x), env: {} });
    expect(await run('--issuer', r.credential.issuer, '--log-key', r.credential.sanad.log.logKey)).toBe(64);
    expect(err.join('\n')).toMatch(/policy/);
    expect(await run('--issuer', r.credential.issuer, '--log-key', r.credential.sanad.log.logKey, '--use-recommended-policy')).toBe(0);
    expect(out.join('\n')).toMatch(/not a verifier policy/);
  });
});
