import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, readdirSync, writeFileSync, appendFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMemoryStore, createFileStore, createSqliteStore, sqliteAvailable, openStore } from '../src/store/index.mjs';

const hasSqlite = sqliteAvailable();
if (!hasSqlite) console.warn('node:sqlite is not available: sqlite store tests are skipped');
const dirs = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'sanad-store-')); dirs.push(d); return d; };
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const adapters = [
  ['memory', () => createMemoryStore(), true],
  ['file', () => createFileStore(tmp()), true],
  ['sqlite', () => createSqliteStore(), hasSqlite],
];

for (const [name, make, enabled] of adapters) {
  describe.skipIf(!enabled)(`store behaviour: ${name}`, () => {
    it('get returns null for a missing record, put upserts', () => {
      const s = make();
      expect(s.get('c', 'a')).toBeNull();
      s.put('c', 'a', { n: 1 });
      s.put('c', 'a', { n: 2, list: [1, 'x', null] });
      expect(s.get('c', 'a')).toEqual({ n: 2, list: [1, 'x', null] });
      s.close();
    });
    it('isolates stored state from callers (deep copy)', () => {
      const s = make();
      const v = { a: { b: [1] } };
      s.put('c', 'x', v);
      v.a.b.push(2);
      const got = s.get('c', 'x');
      expect(got).toEqual({ a: { b: [1] } });
      got.a.b.push(9);
      expect(s.get('c', 'x')).toEqual({ a: { b: [1] } });
      s.list('c')[0].a.b.push(7);
      expect(s.get('c', 'x')).toEqual({ a: { b: [1] } });
      s.append('st', v); v.a.b.push(3);
      const r = s.read('st'); r[0].a.b.push(5);
      expect(s.read('st')[0]).toEqual({ a: { b: [1, 2] } });
      s.close();
    });
    it('lists sorted by id in code unit order, per collection', () => {
      const s = make();
      for (const id of ['b', 'B', 'a', 'did:key:z2', 'A', 'a.1', 'a-1', '10', '9']) s.put('c', id, id);
      s.put('other', 'z', 'no');
      expect(s.list('c')).toEqual(['10', '9', 'A', 'B', 'a', 'a-1', 'a.1', 'b', 'did:key:z2']);
      expect(s.list('empty')).toEqual([]);
      s.close();
    });
    it('stores ids differing only in case separately', () => {
      const s = make();
      s.put('c', 'Abc', 1); s.put('c', 'abc', 2); s.put('c', 'ABC', 3);
      expect([s.get('c', 'Abc'), s.get('c', 'abc'), s.get('c', 'ABC')]).toEqual([1, 2, 3]);
      expect(s.list('c')).toHaveLength(3);
      s.close();
    });
    it('accepts DIDs and long ids, and distinguishes collections differing in case', () => {
      const s = make();
      const ids = ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', 'did:web:a.example:x', 'a'.repeat(200), 'Z'.repeat(200)];
      for (const id of ids) s.put('dids', id, id);
      for (const id of ids) expect(s.get('dids', id)).toBe(id);
      s.put('Dids', 'x', 1);
      expect(s.get('dids', 'x')).toBeNull();
      s.close();
    });
    it('rejects bad ids, collections and streams', () => {
      const s = make();
      const bad = ['../x', 'a/b', 'a\\b', '..', '.', '', 'a'.repeat(201), 'a b', 'é', 5, null, undefined];
      for (const b of bad) {
        expect(() => s.put('c', b, 1)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.get('c', b)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.put(b, 'a', 1)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.list(b)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.append(b, 1)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.read(b)).toThrow(expect.objectContaining({ code: 'bad_id' }));
        expect(() => s.size(b)).toThrow(expect.objectContaining({ code: 'bad_id' }));
      }
      s.close();
    });
    it('rejects values that are not JSON', () => {
      const s = make();
      expect(() => s.put('c', 'a', undefined)).toThrow(expect.objectContaining({ code: 'bad_value' }));
      expect(() => s.put('c', 'a', () => 1)).toThrow(expect.objectContaining({ code: 'bad_value' }));
      const cyc = {}; cyc.self = cyc;
      expect(() => s.put('c', 'a', cyc)).toThrow(expect.objectContaining({ code: 'bad_value' }));
      s.close();
    });
    it('streams: append returns the index, read ranges, size', () => {
      const s = make();
      expect(s.size('log')).toBe(0);
      expect(s.read('log')).toEqual([]);
      expect([s.append('log', { i: 0 }), s.append('log', 'one'), s.append('log', [2])]).toEqual([0, 1, 2]);
      expect(s.size('log')).toBe(3);
      expect(s.read('log')).toEqual([{ i: 0 }, 'one', [2]]);
      expect(s.read('log', 1)).toEqual(['one', [2]]);
      expect(s.read('log', 1, 2)).toEqual(['one']);
      expect(s.read('log', 3)).toEqual([]);
      expect(() => s.read('log', 0, 4)).toThrow(expect.objectContaining({ code: 'bad_range' }));
      expect(() => s.read('log', -1)).toThrow(expect.objectContaining({ code: 'bad_range' }));
      expect(s.size('events')).toBe(0);
      s.append('Log', 'case'); expect(s.size('log')).toBe(3); expect(s.size('Log')).toBe(1);
      s.close();
    });
    it('refuses use after close', () => {
      const s = make(); s.close();
      expect(() => s.get('c', 'a')).toThrow(expect.objectContaining({ code: 'store_closed' }));
    });
  });
}

describe('file store specifics', () => {
  it('persists across reopen', () => {
    const d = tmp();
    let s = createFileStore(d);
    s.put('assessments', 'A1', { x: 1 }); s.append('log', { a: 1 }); s.append('log', { a: 2 });
    s.close();
    s = createFileStore(d);
    expect(s.get('assessments', 'A1')).toEqual({ x: 1 });
    expect(s.size('log')).toBe(2);
    expect(s.append('log', { a: 3 })).toBe(2);
    expect(s.read('log')).toEqual([{ a: 1 }, { a: 2 }, { a: 3 }]);
    s.close();
  });
  it('writes atomically and leaves no temporary files', () => {
    const d = tmp(); const s = createFileStore(d);
    for (let i = 0; i < 20; i++) s.put('c', 'k', { i });
    expect(readdirSync(join(d, 'collections', 'c_c'))).toEqual(['i_k.json']);
    s.close();
  });
  it('encodes names so that file names are safe (no uppercase, no colon, bounded length)', () => {
    const d = tmp(); const s = createFileStore(d);
    s.put('c', 'did:key:zAbC', 1); s.put('c', 'Z'.repeat(200), 2);
    for (const f of readdirSync(join(d, 'collections', 'c_c'))) {
      expect(f).toBe(f.toLowerCase());
      expect(f).not.toMatch(/[:<>"/\\|?*]/);
      expect(f.length).toBeLessThanOrEqual(255);
    }
    expect(s.get('c', 'Z'.repeat(200))).toBe(2);
    s.close();
  });
  it('uses private modes', () => {
    if (process.platform === 'win32') return;
    const d = tmp(); const s = createFileStore(d);
    s.put('c', 'a', 1); s.append('log', 1);
    const { statSync } = require_fs();
    expect(statSync(join(d, 'collections')).mode & 0o777).toBe(0o700);
    expect(statSync(join(d, 'collections', 'c_c', 'i_a.json')).mode & 0o777).toBe(0o600);
    expect(statSync(join(d, 'streams', 's_log.jsonl')).mode & 0o777).toBe(0o600);
    s.close();
  });
  it('ignores a truncated last line, reports it, and repairs it on the next append', () => {
    const d = tmp(); let s = createFileStore(d);
    s.append('log', { n: 1 }); s.append('log', { n: 2 }); s.close();
    const f = join(d, 'streams', 's_log.jsonl');
    appendFileSync(f, '{"n":3,"par');
    s = createFileStore(d);
    expect(s.size('log')).toBe(2);
    expect(s.read('log')).toEqual([{ n: 1 }, { n: 2 }]);
    const v = s.verify();
    expect(v.ok).toBe(false);
    expect(v.streams[0]).toMatchObject({ size: 2 });
    expect(v.streams[0].truncatedBytes).toBeGreaterThan(0);
    expect(s.append('log', { n: 4 })).toBe(2);
    expect(s.read('log')).toEqual([{ n: 1 }, { n: 2 }, { n: 4 }]);
    expect(s.verify().ok).toBe(true);
    s.close();
  });
  it('reports a corrupt complete line', () => {
    const d = tmp(); const s = createFileStore(d);
    s.append('log', 1);
    appendFileSync(join(d, 'streams', 's_log.jsonl'), 'not json\n');
    expect(() => s.read('log')).toThrow(expect.objectContaining({ code: 'store_corrupt' }));
    s.close();
  });
  it('stores case-variants separately on disk', () => {
    const d = tmp(); const s = createFileStore(d);
    s.put('c', 'a', 1); s.put('c', 'A', 2);
    expect(readdirSync(join(d, 'collections', 'c_c')).length).toBe(2);
    s.close();
  });
});

import * as fs from 'node:fs';
function require_fs() { return fs; }

describe.skipIf(!hasSqlite)('sqlite store specifics', () => {
  it('shares an existing DatabaseSync with a prefix and does not close it', async () => {
    const { DatabaseSync } = process.getBuiltinModule('node:sqlite');
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE host(x TEXT)');
    const a = createSqliteStore({ db, prefix: 'eng_' });
    const b = createSqliteStore({ db, prefix: 'other_' });
    a.put('c', 'k', 1); b.put('c', 'k', 2); a.append('log', 'x');
    expect(a.get('c', 'k')).toBe(1); expect(b.get('c', 'k')).toBe(2);
    expect(b.size('log')).toBe(0);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map((r) => r.name);
    expect(tables).toEqual(expect.arrayContaining(['eng_kv', 'eng_stream', 'other_kv', 'other_stream', 'host']));
    a.close();
    expect(db.prepare('SELECT 1 AS one').get().one).toBe(1);
    b.close(); db.close();
  });
  it('rejects bad prefixes', () => {
    for (const p of ['1a', 'a-b', '', 'a'.repeat(32), 'x;drop']) expect(() => createSqliteStore({ prefix: p })).toThrow(expect.objectContaining({ code: 'bad_prefix' }));
  });
  it('persists in a file path', () => {
    const p = join(tmp(), 'e.db');
    let s = createSqliteStore({ path: p }); s.put('c', 'k', { v: 1 }); s.append('l', 1); s.close();
    s = createSqliteStore({ path: p });
    expect(s.get('c', 'k')).toEqual({ v: 1 }); expect(s.size('l')).toBe(1); s.close();
  });
});

describe('openStore', () => {
  it('opens each kind', () => {
    expect(openStore('memory').size('x')).toBe(0);
    expect(openStore({ type: 'memory' }).size('x')).toBe(0);
    const f = openStore({ type: 'file', dir: tmp() }); f.put('c', 'a', 1); expect(f.get('c', 'a')).toBe(1);
    if (hasSqlite) expect(openStore({ type: 'sqlite' }).size('x')).toBe(0);
    expect(() => openStore({ type: 'nope' })).toThrow(expect.objectContaining({ code: 'bad_store' }));
    expect(() => openStore(null)).toThrow(expect.objectContaining({ code: 'bad_store' }));
  });
});
