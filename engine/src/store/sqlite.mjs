// SQLite storage adapter on node:sqlite (loaded lazily; absent on some Node versions).
import { EngineError } from '../errors.mjs';
import { checkName, toJson, fromJson, checkRange } from './memory.mjs';

export function loadSqlite() {
  let mod = null;
  try { mod = process.getBuiltinModule?.('node:sqlite') ?? null; } catch { mod = null; }
  if (!mod || !mod.DatabaseSync) throw new EngineError('sqlite_unavailable', 'node:sqlite is not available in this Node version', 500);
  return mod;
}

export function sqliteAvailable() {
  try { loadSqlite(); return true; } catch { return false; }
}

export function createSqliteStore({ path = ':memory:', db = null, prefix = 'sanad_' } = {}) {
  if (typeof prefix !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,30}$/.test(prefix)) throw new EngineError('bad_prefix', 'invalid table prefix');
  const owned = !db;
  const conn = db || new (loadSqlite().DatabaseSync)(path);
  const kv = `${prefix}kv`, st = `${prefix}stream`;
  conn.exec(`CREATE TABLE IF NOT EXISTS ${kv}(collection TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(collection, id))`);
  conn.exec(`CREATE TABLE IF NOT EXISTS ${st}(stream TEXT NOT NULL, idx INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(stream, idx))`);
  const q = {
    get: conn.prepare(`SELECT value FROM ${kv} WHERE collection = ? AND id = ?`),
    put: conn.prepare(`INSERT INTO ${kv}(collection, id, value) VALUES(?, ?, ?) ON CONFLICT(collection, id) DO UPDATE SET value = excluded.value`),
    list: conn.prepare(`SELECT value FROM ${kv} WHERE collection = ? ORDER BY id`),
    size: conn.prepare(`SELECT COUNT(*) AS n FROM ${st} WHERE stream = ?`),
    append: conn.prepare(`INSERT INTO ${st}(stream, idx, value) VALUES(?, ?, ?)`),
    read: conn.prepare(`SELECT value FROM ${st} WHERE stream = ? AND idx >= ? AND idx < ? ORDER BY idx`),
  };
  let closed = false;
  const open = () => { if (closed) throw new EngineError('store_closed', 'store is closed', 500); };
  const size = (s) => Number(q.size.get(s).n);
  return {
    get(collection, id) {
      open(); checkName(collection, 'collection'); checkName(id);
      const r = q.get.get(collection, id);
      return r ? fromJson(r.value) : null;
    },
    put(collection, id, value) {
      open(); checkName(collection, 'collection'); checkName(id);
      q.put.run(collection, id, toJson(value));
    },
    list(collection) {
      open(); checkName(collection, 'collection');
      return q.list.all(collection).map((r) => fromJson(r.value));
    },
    append(stream, value) {
      open(); checkName(stream, 'stream');
      const text = toJson(value);
      const n = size(stream);
      q.append.run(stream, n, text);
      return n;
    },
    read(stream, from = 0, to) {
      open(); checkName(stream, 'stream');
      const [f, t] = checkRange(from, to, size(stream));
      return q.read.all(stream, f, t).map((r) => fromJson(r.value));
    },
    size(stream) { open(); checkName(stream, 'stream'); return size(stream); },
    close() { if (closed) return; closed = true; if (owned) conn.close(); },
  };
}
