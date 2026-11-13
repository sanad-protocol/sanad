// Regression tests for the principles of Sanad. If one of these fails, a design principle has been changed, not just a detail.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as H from './helpers.mjs';
import { core, createHttpServer, createEngine, prepareCommit } from '../src/index.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const files = (d, out = []) => {
  for (const n of readdirSync(d)) {
    if (n === 'node_modules') continue;
    const p = join(d, n);
    if (statSync(p).isDirectory()) files(p, out); else if (/\.(mjs|js|json|md|html|css|ts)$/.test(n) || n === 'sanad-engine') out.push(p);
  }
  return out;
};
const docsRoot = fileURLToPath(new URL('../../docs/', import.meta.url));
const all = [...files(root), ...files(docsRoot)].filter((f) => !/test\/philosophy\.test\.mjs$/.test(f));
const read = (f) => readFileSync(f, 'utf8');
const rel = (f) => relative(root, f);
const code = (f) => /\/(src|static)\//.test(f) || /dist\/sanad-engine\.mjs$/.test(f);

it('the scan covers the whole engine tree', () => { expect(all.length).toBeGreaterThan(30); expect(all.some((f) => f.endsWith('TUTORIAL-plug-sanad-into-any-system.md'))).toBe(true); });

describe('Sanad is a protocol and Kamangir is one host among many', () => {
  it('nothing in the engine tree (sources, page, bundle, examples, documents) names any one host', () => {
    for (const f of all.filter((f) => !f.includes('vectors/engine-'))) expect(read(f), rel(f)).not.toMatch(/kamangir|kg-s3|persian[_ ]math/i);
  });
  it('the design says that no host has a special status', () => {
    expect(read(join(root, 'DESIGN.md'))).toMatch(/no special status/);
  });
});

describe('neutral institutional voice', () => {
  it('no tool or vendor branding, co-author trailers or generation notices anywhere in the engine tree', () => {
    for (const f of all) expect(read(f), rel(f)).not.toMatch(/claude|anthropic|co-authored-by|generated with|\bAI[- ]assisted\b|\bchatgpt\b/i);
  });
  it('documents are written in the third person', () => {
    for (const f of all.filter((f) => f.endsWith('.md'))) expect(read(f), rel(f)).not.toMatch(/(^|[\s(])I('m|'ll|'ve| am| will| have| think| believe)?\s/m);
  });
});

describe('decentralised assessment, never accreditation', () => {
  it('every mention of accreditation is a denial', () => {
    for (const f of all) for (const line of read(f).split('\n')) {
      if (!/accredit/i.test(line)) continue;
      expect(line, rel(f) + ': ' + line.trim()).toMatch(/\b(not|never|no|nor|without|neither)\b|is not|does not|refus/i);
    }
  });
  it('the README and DESIGN say that nobody vets attestors and that the template policy is only a recommendation', () => {
    for (const f of ['README.md', 'DESIGN.md']) { const t = read(join(root, f)); expect(t, f).toMatch(/nobody vets/i); expect(t, f).toMatch(/recommend/i); }
  });
  it('the template policy only recommends: one credential, two verifier policies, two answers, and the recommendation is labelled as such', () => {
    const { engine, clock, people: P } = H.setup(); H.newAssessment(engine);
    const inv = ['A', 'B'].map((n) => engine.invite('as-1', { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(engine, P['AB'[k]], 'as-1', i.attestationId, 4).secret);
    sec.forEach((s, k) => H.revealAs(engine, P['AB'[k]], 'as-1', s));
    clock.advance(1000);
    const doc = engine.finalize('as-1');
    const own = engine.verifyCredential(doc, { useRecommendedPolicy: true }).recognition;
    const strict = engine.verifyCredential(doc, { policy: { minAttestors: 3, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 0, minAgreement: 0, maxInferenceDepth: 0, inferenceDecay: 0.8, asOf: '2026-03-01' } }).recognition;
    expect(own.status).toBe('recognised'); expect(strict.status).toBe('provisional');
    expect(doc.sanad.policy.id).toBe('p1'); // carried as data
    expect(Object.keys(doc.sanad.policy)).toContain('minAttestors');
  });
  it('no source file offers a way to vet, rank, admit or certify attestors', () => {
    for (const f of all.filter((f) => /\/src\//.test(f))) expect(read(f), rel(f)).not.toMatch(/\b(allowlist|whitelist|approvedAttestors|certifiedAttestors|vetAttestor|rankAttestor)\b/i);
  });
});

describe('blind commit, then reveal', () => {
  const setupTwo = () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    return { ...s, inv };
  };
  it('no reveal before every invited attestor has committed (or the commit deadline passed)', () => {
    const { engine, people: P, inv } = setupTwo();
    const { secret } = H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 4);
    H.code(() => H.revealAs(engine, P.A, 'as-1', secret), 'reveal_not_open');
  });
  it('a commit cannot be copied from another examiner', () => {
    const { engine, people: P, inv } = setupTwo();
    H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 4);
    const stored = engine.getAssessment('as-1', { view: 'operator' }).commits[inv[0].attestationId];
    H.code(() => engine.commit('as-1', { attestationId: inv[1].attestationId, payload: stored.payload, jws: stored.jws }), 'commit_mismatch_invitation');
  });
  it('the public view shows neither marks nor nonces before the reveal phase opens', () => {
    const { engine, people: P, inv } = setupTwo();
    const { secret } = H.commitAs(engine, P.A, 'as-1', inv[0].attestationId, 4);
    const pub = JSON.stringify(engine.getAssessment('as-1'));
    expect(pub).not.toContain(secret.nonce);
    expect(engine.getAssessment('as-1').reveals).toEqual({});
  });
  it('the commit hides the mark: the same level under different nonces gives different commits', () => {
    const a = core.commitOf({ attestor: 'did:key:za', evidence: 'e', level: 3, nonce: 'a'.repeat(22) });
    const b = core.commitOf({ attestor: 'did:key:za', evidence: 'e', level: 3, nonce: 'b'.repeat(22) });
    expect(a).not.toBe(b);
  });
  it('a nonce too short to hide a level from a 6-value space is refused', () => {
    const { engine, people: P, inv } = setupTwo();
    expect(() => prepareCommit({ signer: P.A.signer, assessment: engine.getAssessment('as-1'), attestationId: inv[0].attestationId, level: 3, nonce: 'short' })).toThrow(/nonce/);
  });
});

describe('attestors hold their own private keys', () => {
  const noKeys = /privateKey|pkcs8|importPrivateKey|generateKeyPair|exportPrivateKey|demo-keys/;
  it('the engine, the HTTP server, the verifier and the stores never touch private keys', () => {
    for (const f of ['src/engine.mjs', 'src/http.mjs', 'src/bundle.mjs', 'src/store/memory.mjs', 'src/store/file.mjs', 'src/store/sqlite.mjs', 'src/store/index.mjs']) {
      const text = read(join(root, f)).split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
      expect(text, f).not.toMatch(noKeys);
    }
  });
  it('the demonstration key helper is imported by no engine, server, verifier or CLI module', () => {
    for (const f of readdirSync(join(root, 'src')).filter((n) => n.endsWith('.mjs') && n !== 'demo-keys.mjs' && n !== 'index.mjs')) expect(read(join(root, 'src', f)), f).not.toMatch(/demo-keys/);
  });
  it('after a complete run, nothing the engine stored contains a private key, even one posted by mistake', () => {
    const { engine, store, people: P, clock } = H.setup(); H.newAssessment(engine);
    const inv = ['A', 'B'].map((n) => engine.invite('as-1', { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => {
      const n = 'AB'[k];
      const { request, secret } = prepareCommit({ signer: P[n].signer, assessment: engine.getAssessment('as-1'), attestationId: i.attestationId, level: 3 });
      engine.commit('as-1', { ...request, privateKey: P[n].privateKeyPkcs8 }); // a careless client sends its key along
      return secret;
    });
    sec.forEach((s, k) => H.revealAs(engine, P['AB'[k]], 'as-1', s));
    clock.advance(1000); engine.finalize('as-1');
    const dump = JSON.stringify([store.list('assessments'), store.list('credentials'), store.list('templates'), store.list('dids'), store.read('log'), store.read('events')]);
    for (const n of ['A', 'B']) expect(dump).not.toContain(P[n].privateKeyPkcs8);
  });
  it('the engine has no method that takes or returns an attestor key', () => {
    const { engine } = H.setup();
    for (const k of Object.keys(engine)) expect(k, k).not.toMatch(/key|sign|secret/i);
  });
});

describe('no names or personal data enter the engine', () => {
  it('a subject must be a pseudonymous URN; a name or an e-mail address is refused', () => {
    const { engine } = H.setup();
    for (const subject of ['Ada Lovelace', 'ada@example.org', '', 'urn:uuid: spaces', 42]) H.code(() => H.newAssessment(engine, { subject }), 'bad_subject');
    expect(H.newAssessment(engine, { id: 'ok-1', subject: 'urn:uuid:11111111-1111-4111-8111-111111111111' }).id).toBe('ok-1');
  });
  it('log leaves hold only a kind, a hash and a time', () => {
    const { engine, people: P, clock } = H.setup(); H.newAssessment(engine);
    const inv = ['A', 'B'].map((n) => engine.invite('as-1', { attestor: P[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(engine, P['AB'[k]], 'as-1', i.attestationId, 2).secret);
    sec.forEach((s, k) => H.revealAs(engine, P['AB'[k]], 'as-1', s)); clock.advance(1000); engine.finalize('as-1');
    for (const e of engine.log.entries()) { const l = JSON.parse(e.leaf); expect(Object.keys(l).sort()).toEqual(['kind', 'ref', 'ts']); expect(l.ref).toMatch(/^[0-9a-f]{64}$/); }
  });
});

describe('no central authority, no token, no fee, no network in the protocol path', () => {
  it('the engine core, keys and verifier never open a network connection', () => {
    for (const f of ['src/engine.mjs', 'src/keys.mjs', 'src/bundle.mjs', 'src/commit.mjs', 'src/log.mjs', 'src/template.mjs', 'src/stats.mjs']) expect(read(join(root, f)), f).not.toMatch(/node:(http|https|net|dns|tls|dgram)|\bfetch\(|XMLHttpRequest|WebSocket/);
  });
  it('no payment, fee, wallet or on-chain concept appears in the source', () => {
    for (const f of all.filter((f) => /\/src\//.test(f))) expect(read(f), rel(f)).not.toMatch(/\b(invoice|stripe|paypal|wallet|blockchain|cryptocurrency|smart contract|payment)\b/i);
  });
  it('the README states that the protocol has no fee and no token', () => { expect(read(join(root, 'README.md'))).toMatch(/no fee/i); expect(read(join(root, 'README.md'))).toMatch(/no token/i); });
});

describe('honest limits are stated', () => {
  it('README and DESIGN say there has been no cryptographic review and that collusion cannot be proved', () => {
    for (const f of ['README.md', 'DESIGN.md']) { const t = read(join(root, f)); expect(t, f).toMatch(/no external cryptographic review|not been (externally )?reviewed/i); expect(t, f).toMatch(/collusion/i); }
  });
  it('the integration tutorial marks what is untested', () => { expect(read(join(docsRoot, 'TUTORIAL-plug-sanad-into-any-system.md'))).toMatch(/untested/i); });
});

describe('claims are not stronger than what is checked (review round)', () => {
  it('the README and DESIGN say that commit-before-reveal ordering is operator-attested and that did:web and statistics are issuer assertions', () => {
    for (const f of ['README.md', 'DESIGN.md']) { const t = read(join(root, f)); expect(t, f).toMatch(/operator-attested|attested by the operator/i); expect(t, f).toMatch(/did:web[^.]*operator-asserted|operator-asserted/i); }
    expect(read(join(root, 'DESIGN.md'))).toMatch(/not recomputable from the log/);
    expect(read(join(root, 'README.md'))).not.toMatch(/marks cannot be copied/i);
  });
  it('no document claims that statistics are recomputable from the log or that any verifier sees tampering', () => {
    for (const f of all.filter((f) => f.endsWith('.md'))) for (const line of read(f).split('\n')) {
      if (/statistics[^.]*recomputable from the (hash-only )?log/i.test(line)) expect(line, rel(f)).toMatch(/\b(not|cannot|no)\b/i);
      expect(line, rel(f)).not.toMatch(/any verifier sees it/i);
    }
  });
  it('the experimental, not cryptographically reviewed notice is in every verification report and in the CLI texts', () => {
    const { engine } = H.setup(); const r = engine.verifyCredential({}, {});
    expect(r.notice).toMatch(/Experimental/); expect(r.notice).toMatch(/not been cryptographically reviewed/);
    expect(read(join(root, 'src/cli.mjs'))).toMatch(/NOTICE/);
  });
  it('the decisions that were deliberately not taken are written down', () => {
    const t = read(join(docsRoot, 'SPEC-DECISIONS-NEEDED.md'));
    for (const h of ['commit statements', 'attestor signature', 'conflictDeclared', 'statistics', 'Agreement', 'proof format', 'Evidence hash', 'Level 6', 'did:web', 'month']) expect(t, h).toContain(h);
  });
});

