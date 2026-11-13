import { describe, it, expect } from 'vitest';
import { newNonce, NONCE_RE, commitFor, commitStatement, attestationStatement, checkCommit, checkReveal } from '../src/commit.mjs';
import { commitOf } from '../src/core.mjs';

const H = 'a'.repeat(64);
const inv = { attestationId: 'A1.a01', attestor: 'did:key:z6Mkx', evidence: 'A1.E1', role: 'examiner' };
const asm = { id: 'A1', templateHash: H };
const nonce = newNonce();
const base = () => {
  const level = 3, commit = commitFor({ attestor: inv.attestor, evidence: inv.evidence, level, nonce });
  return { commit, statement: attestationStatement({ id: inv.attestationId, attestor: inv.attestor, evidence: inv.evidence, level, role: inv.role, conflictDeclared: false, date: '2026-05-02', commit, nonce }) };
};
const reveal = (over = {}, extra = {}) => {
  const { commit, statement } = base();
  return () => checkReveal({ statement: { ...statement, ...over }, invitation: inv, storedCommit: commit, evidenceDate: '2026-05-01', revealDay: '2026-05-10', ...extra });
};
const code = (fn, c) => expect(fn).toThrow(expect.objectContaining({ name: 'EngineError', code: c }));

describe('nonce and commit', () => {
  it('nonces are 22 chars, distinct and match NONCE_RE', () => {
    const seen = new Set();
    for (let i = 0; i < 100; i++) { const n = newNonce(); expect(n).toMatch(/^[A-Za-z0-9_-]{22}$/); expect(NONCE_RE.test(n)).toBe(true); seen.add(n); }
    expect(seen.size).toBe(100);
    expect(NONCE_RE.test('a'.repeat(21))).toBe(false); expect(NONCE_RE.test('a'.repeat(129))).toBe(false); expect(NONCE_RE.test('a'.repeat(21) + '+')).toBe(false);
  });
  it('commit equals the core commit and binds every field; property over all levels', () => {
    const f = { attestor: 'did:key:zA', evidence: 'E1', level: 2, nonce };
    expect(commitFor(f)).toBe(commitOf(f));
    expect(commitFor(f)).toMatch(/^[0-9a-f]{64}$/);
    for (let level = 0; level <= 5; level++) {
      const c = commitFor({ ...f, level });
      expect(commitFor({ ...f, level })).toBe(c);
      for (let other = 0; other <= 5; other++) if (other !== level) expect(commitFor({ ...f, level: other })).not.toBe(c);
      expect(commitFor({ ...f, level, attestor: 'did:key:zB' })).not.toBe(c);
      expect(commitFor({ ...f, level, evidence: 'E2' })).not.toBe(c);
      expect(commitFor({ ...f, level, nonce: newNonce() })).not.toBe(c);
    }
  });
});

describe('statements', () => {
  it('commitStatement is closed and validated', () => {
    const s = commitStatement({ assessment: 'A1', attestationId: 'A1.a01', attestor: 'd', evidence: 'e', role: 'r', commit: H, templateHash: H });
    expect(Object.keys(s).sort()).toEqual(['assessment', 'attestationId', 'attestor', 'commit', 'evidence', 'role', 'templateHash', 'type']);
    expect(s.type).toBe('sanad-commit');
    for (const k of ['assessment', 'attestationId', 'attestor', 'evidence', 'role']) code(() => commitStatement({ ...s, [k]: 5 }), 'bad_commit');
    code(() => commitStatement({ ...s, commit: 'A'.repeat(64) }), 'bad_commit');
    code(() => commitStatement({ ...s, commit: 'ab' }), 'bad_commit');
    code(() => commitStatement({ ...s, templateHash: undefined }), 'bad_commit');
  });
  it('attestationStatement has exactly nine members', () => {
    const { statement } = base();
    expect(Object.keys(statement).sort()).toEqual(['attestor', 'commit', 'conflictDeclared', 'date', 'evidence', 'id', 'level', 'nonce', 'role']);
  });
});

describe('checkCommit', () => {
  const good = () => commitStatement({ assessment: 'A1', attestationId: inv.attestationId, attestor: inv.attestor, evidence: inv.evidence, role: inv.role, commit: H, templateHash: H });
  it('accepts a matching payload', () => { expect(() => checkCommit({ payload: good(), invitation: inv, assessment: asm })).not.toThrow(); });
  it('bad_commit for shape problems', () => {
    code(() => checkCommit({ payload: null, invitation: inv, assessment: asm }), 'bad_commit');
    code(() => checkCommit({ payload: { ...good(), extra: 1 }, invitation: inv, assessment: asm }), 'bad_commit');
    const { role, ...missing } = good();
    code(() => checkCommit({ payload: missing, invitation: inv, assessment: asm }), 'bad_commit');
    code(() => checkCommit({ payload: { ...good(), commit: 'xyz' }, invitation: inv, assessment: asm }), 'bad_commit');
  });
  it('commit_mismatch_invitation for each differing field', () => {
    for (const [k, v] of Object.entries({ type: 'other', assessment: 'A2', attestationId: 'A1.a02', attestor: 'did:key:zOther', evidence: 'A1.E2', role: 'x', templateHash: 'b'.repeat(64) })) {
      code(() => checkCommit({ payload: { ...good(), [k]: v }, invitation: inv, assessment: asm }), 'commit_mismatch_invitation');
    }
  });
});

describe('checkReveal', () => {
  it('accepts a good reveal, with and without optional bounds', () => {
    expect(reveal()).not.toThrow();
    expect(reveal({}, { evidenceDate: undefined, revealDay: undefined, allowedLevels: undefined })).not.toThrow();
    expect(reveal({}, { allowedLevels: [3] })).not.toThrow();
    expect(reveal({ date: '2026-05-01' })).not.toThrow(); expect(reveal({ date: '2026-05-10' })).not.toThrow();
  });
  it('bad_statement', () => {
    code(reveal({ extra: 1 }), 'bad_statement');
    code(reveal({ conflictDeclared: 'no' }), 'bad_statement');
    code(reveal({ conflictDeclared: undefined }), 'bad_statement');
    code(reveal({ role: 4 }), 'bad_statement');
    code(() => checkReveal({ statement: null, invitation: inv, storedCommit: H }), 'bad_statement');
    code(() => checkReveal({ statement: [], invitation: inv, storedCommit: H }), 'bad_statement');
  });
  it('statement_mismatch', () => {
    for (const [k, v] of Object.entries({ id: 'A1.a09', attestor: 'did:key:zX', evidence: 'A1.E9', role: 'other' })) code(reveal({ [k]: v }), 'statement_mismatch');
  });
  it('commit_mismatch', () => {
    code(reveal({ level: 4 }), 'commit_mismatch');
    code(reveal({ commit: H }), 'commit_mismatch');
    code(reveal({ nonce: newNonce() }), 'commit_mismatch');
    const { statement } = base();
    code(() => checkReveal({ statement, invitation: inv, storedCommit: H }), 'commit_mismatch');
    // statement.commit equals the stored one but is not the commit of its own content
    code(() => checkReveal({ statement: { ...statement, level: 1 }, invitation: inv, storedCommit: statement.commit }), 'commit_mismatch');
  });
  it('bad_level', () => {
    for (const lv of [-1, 6, 2.5, '3', null, NaN]) code(reveal({ level: lv }), 'bad_level');
    code(reveal({}, { allowedLevels: [0, 1, 2] }), 'bad_level');
  });
  it('bad_date', () => {
    for (const d of ['2026-02-30', '2026-5-2', 'tomorrow', 20260502, null, '2026-05-02T00:00:00Z']) code(reveal({ date: d }), 'bad_date');
    code(reveal({ date: '2026-04-30' }), 'bad_date');
    code(reveal({ date: '2026-05-11' }), 'bad_date');
  });
  it('bad_nonce', () => {
    code(reveal({ nonce: 'short' }), 'bad_nonce');
    code(reveal({ nonce: 'a'.repeat(21) + '!' }), 'bad_nonce');
    code(reveal({ nonce: 7 }), 'bad_nonce');
  });
  it('every level 0..5 reveals correctly', () => {
    for (let level = 0; level <= 5; level++) {
      const n = newNonce(), commit = commitFor({ attestor: inv.attestor, evidence: inv.evidence, level, nonce: n });
      const statement = attestationStatement({ id: inv.attestationId, attestor: inv.attestor, evidence: inv.evidence, level, role: inv.role, conflictDeclared: true, date: '2026-05-02', commit, nonce: n });
      expect(() => checkReveal({ statement, invitation: inv, storedCommit: commit, evidenceDate: '2026-05-01', revealDay: '2026-05-10' })).not.toThrow();
    }
  });
});
