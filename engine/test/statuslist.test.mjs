import { describe, it, expect } from 'vitest';
import { gunzipSync } from 'node:zlib';
import * as H from './helpers.mjs';
import { newBitstring, setBit, getBit, encodeList, decodeList, statusEntry, statusEntryProblems, buildStatusListCredential, checkStatus, STATUS_LIST_TYP, MIN_LIST_BITS, createEngine, createMemoryStore, makeSigner, keyPairFromSeed, createHttpServer, fromB64u } from '../src/index.mjs';

const URL1 = 'https://example.org/sanad/status/revocation-1.json';

function issueTwo({ ttlHours } = {}) {
  const ref = H.setup();
  const issuer = ref.issuer, logSigner = ref.logSigner, people = ref.people;
  const clock = H.makeClock();
  const engine = createEngine({ store: createMemoryStore(), issuer, logSigner, clock, status: { url: URL1, ...(ttlHours ? { ttlHours } : {}) } });
  engine.registerTemplate(H.template());
  const docs = [];
  for (const id of ['as-1', 'as-2']) {
    H.newAssessment(engine, { id });
    const inv = ['A', 'B'].map((n) => engine.invite(id, { attestor: people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(engine, people['AB'[k]], id, i.attestationId, 4).secret);
    sec.forEach((x, k) => H.revealAs(engine, people['AB'[k]], id, x));
    docs.push(engine.finalize(id));
  }
  return { engine, docs, clock, issuer, logSigner };
}
const verify = (engine, doc, extra = {}) => engine.verifyCredential(doc, { useRecommendedPolicy: true, now: Date.parse('2026-03-02T00:00:00Z'), ...extra });
const statusCheck = (r) => r.checks.find((c) => c.name === 'revocation');

describe('bitstring', () => {
  it('index 0 is the most significant bit of the first byte', () => {
    const b = newBitstring(); setBit(b, 0); setBit(b, 9);
    expect(b[0]).toBe(0x80); expect(b[1]).toBe(0x40);
    expect(getBit(b, 0)).toBe(true); expect(getBit(b, 1)).toBe(false); expect(getBit(b, 9)).toBe(true);
    setBit(b, 0, false); expect(b[0]).toBe(0);
  });
  it('the minimum size is 131072 bits and bounds are enforced', () => {
    expect(newBitstring().length * 8).toBe(MIN_LIST_BITS);
    expect(() => newBitstring(1000)).toThrow(RangeError);
    const b = newBitstring(); expect(() => getBit(b, MIN_LIST_BITS)).toThrow(RangeError); expect(() => setBit(b, -1)).toThrow(RangeError);
  });
  it('encodeList is "u" + base64url(gzip) and decodeList inverts it', () => {
    const b = newBitstring(); setBit(b, 5); setBit(b, 99999);
    const enc = encodeList(b);
    expect(enc[0]).toBe('u');
    const raw = gunzipSync(Buffer.from(fromB64u(enc.slice(1))));
    expect(raw.length).toBe(16384); expect(raw[0]).toBe(0x04);
    expect(Array.from(decodeList(enc))).toEqual(Array.from(b));
  });
  it('decodeList refuses a wrong prefix, a short list and garbage', () => {
    expect(() => decodeList('zabc')).toThrow(); expect(() => decodeList('u!!')).toThrow(); expect(() => decodeList(encodeList(new Uint8Array(100)))).toThrow(/shorter/);
  });
  it('a decompression bomb is refused (output is capped)', () => {
    expect(() => decodeList(encodeList(new Uint8Array(40 * 1024 * 1024)))).toThrow();
  });
});

describe('credentialStatus entry', () => {
  it('has the five W3C members and a position as a decimal string', () => {
    const e = statusEntry({ listUrl: URL1, index: 7 });
    expect(e).toEqual({ id: URL1 + '#7', type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: URL1 });
    expect(statusEntryProblems(e)).toEqual([]);
    expect(statusEntryProblems({ ...e, statusPurpose: 'suspension' }).join()).toMatch(/revocation/);
    expect(statusEntryProblems({ ...e, statusListIndex: '07' }).join()).toMatch(/decimal/);
    expect(statusEntryProblems({ ...e, id: URL1 + '#8' }).join()).toMatch(/id must be/);
    expect(statusEntryProblems({ ...e, extra: 1 }).join()).toMatch(/exactly/);
  });
});

describe('issuing, revoking and checking', () => {
  it('each credential gets its own position and the entry is covered by the issuer signature', () => {
    const { docs, engine } = issueTwo();
    expect(docs.map((d) => d.credentialStatus.statusListIndex)).toEqual(['0', '1']);
    expect(docs[0].credentialStatus.statusListCredential).toBe(URL1);
    expect(verify(engine, docs[0]).checks.find((c) => c.name === 'shape').ok).toBe(true);
    const t = JSON.parse(JSON.stringify(docs[0])); t.credentialStatus = statusEntry({ listUrl: URL1, index: 5 });
    expect(verify(engine, t).ok).toBe(false);
  });
  it('before revocation the list says clear; after revocation only that credential fails', () => {
    const { engine, docs } = issueTwo();
    const list0 = engine.statusListCredential();
    expect(statusCheck(verify(engine, docs[0], { statusLists: [list0] })).ok).toBe(true);
    expect(engine.revokeCredential(docs[0].id, { reason: 'issued in error' })).toMatchObject({ revoked: docs[0].id, index: 0, already: false });
    expect(engine.revokeCredential(docs[0].id).already).toBe(true);
    const list1 = engine.statusListCredential();
    const r0 = verify(engine, docs[0], { statusLists: [list1] }), r1 = verify(engine, docs[1], { statusLists: [list1] });
    expect(statusCheck(r0).ok).toBe(false); expect(statusCheck(r0).detail).toMatch(/revoked: bit 0/);
    expect(r0.ok).toBe(false);
    expect(statusCheck(r1).ok).toBe(true); expect(r1.ok).toBe(true);
    // the old list (taken before the revocation) still says clear: freshness is the verifier's job (validUntil)
    expect(statusCheck(verify(engine, docs[0], { statusLists: [list0] })).ok).toBe(true);
  });
  it('a missing list is a warning, or a failure with requireStatus', () => {
    const { engine, docs } = issueTwo();
    const r = verify(engine, docs[0]);
    expect(statusCheck(r)).toBeUndefined(); expect(r.ok).toBe(true); expect(r.warnings.join()).toMatch(/revocation not checked/);
    const s = verify(engine, docs[0], { requireStatus: true });
    expect(statusCheck(s).ok).toBe(false); expect(s.ok).toBe(false);
    expect(statusCheck(verify(engine, docs[0], { statusLists: [] })).detail).toMatch(/was not supplied/);
  });
  it('a list that is stale, from the future, forged, re-labelled or from another issuer is refused', () => {
    const { engine, docs, issuer } = issueTwo({ ttlHours: 24 });
    const list = engine.statusListCredential();
    const at = (t) => statusCheck(verify(engine, docs[0], { statusLists: [list], now: Date.parse(t) }));
    expect(at('2026-03-01T20:00:00Z').ok).toBe(true);
    expect(at('2026-03-03T00:00:00Z').ok).toBe(false); expect(at('2026-03-03T00:00:00Z').detail).toMatch(/expired/);
    expect(at('2026-02-01T00:00:00Z').detail).toMatch(/dated after/);
    const forged = JSON.parse(JSON.stringify(list)); { const z = newBitstring(); setBit(z, 3); forged.credentialSubject.encodedList = encodeList(z); }
    expect(statusCheck(verify(engine, docs[0], { statusLists: [forged] })).detail).toMatch(/signature is refused/);
    const other = makeSigner(keyPairFromSeed(H.seedOf(77)).privateKey);
    const foreign = buildStatusListCredential({ url: URL1, issuer: other, bytes: newBitstring(), now: Date.parse('2026-03-01T09:00:00Z') });
    expect(statusCheck(verify(engine, docs[0], { statusLists: [foreign] })).detail).toMatch(/not by the credential's issuer/);
    // a list signed for another purpose (credential typ) is not accepted
    const wrongTyp = JSON.parse(JSON.stringify(list)); const { proof, ...body } = wrongTyp;
    wrongTyp.proof = { ...proof, jws: issuer.sign('sanad-credential+jws', body) };
    expect(statusCheck(verify(engine, docs[0], { statusLists: [wrongTyp] })).ok).toBe(false);
    expect(STATUS_LIST_TYP).toBe('sanad-status-list+jws');
  });
  it('checkStatus on a credential without credentialStatus is a no-op', () => {
    expect(checkStatus({ credential: {}, lists: [], now: 0, resolver: null })).toMatchObject({ ok: true, applicable: false });
  });
  it('an engine without a list issues credentials without the member and refuses to revoke', () => {
    const s = H.setup(); H.newAssessment(s.engine);
    const inv = ['A', 'B'].map((n) => s.engine.invite('as-1', { attestor: s.people[n].did, role: 'examiner', evidence: 'E1' }));
    const sec = inv.map((i, k) => H.commitAs(s.engine, s.people['AB'[k]], 'as-1', i.attestationId, 4).secret);
    sec.forEach((x, k) => H.revealAs(s.engine, s.people['AB'[k]], 'as-1', x));
    const doc = s.engine.finalize('as-1');
    expect('credentialStatus' in doc).toBe(false);
    H.code(() => s.engine.revokeCredential(doc.id), 'no_status_list');
    H.code(() => s.engine.statusListCredential(), 'no_status_list');
    expect(() => createEngine({ store: createMemoryStore(), issuer: s.issuer, logSigner: s.logSigner, status: { url: 'not a url' } })).toThrow(/status must be/);
  });
  it('HTTP: revoke is an operator route and the list is public', async () => {
    const { engine, docs } = issueTwo();
    const server = createHttpServer({ engine, operatorToken: 'operator-token-0123456789' });
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    const base = 'http://127.0.0.1:' + server.address().port;
    const post = (token) => fetch(base + '/v1/credentials/' + encodeURIComponent(docs[0].id) + '/revoke', { method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify({ reason: 'x' }) });
    expect((await post(null)).status).toBe(401);
    expect((await post('operator-token-0123456789')).status).toBe(200);
    const list = await (await fetch(base + '/v1/status/revocation')).json();
    expect(list.type).toContain('BitstringStatusListCredential');
    expect(getBit(decodeList(list.credentialSubject.encodedList), 0)).toBe(true);
    await new Promise((ok) => server.close(ok));
  });
});
