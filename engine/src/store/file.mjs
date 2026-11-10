// File storage adapter.
//
// Layout under `dir`:
//   collections/c_<name>/i_<name>.json   one record per file, content { "id": ..., "value": ... }
//   streams/s_<name>.jsonl               one JSON value per line
//
// Name encoding (injective, safe on case-insensitive and Windows file systems):
//   an uppercase letter X becomes '+x', ':' becomes '=', every other allowed character is kept
//   (the allowed set has no '+' or '='). Names whose encoding exceeds 150 characters become
//   'h' + SHA-256 hex of the name. Each name carries a fixed prefix (c_, i_, s_) so that
//   reserved Windows device names never occur. The real id is stored inside the file,
//   so listing never needs to decode a file name.
import {
  mkdirSync, readFileSync, writeFileSync, renameSync, readdirSync, existsSync, openSync, closeSync,
  fsyncSync, writeSync, ftruncateSync, unlinkSync, lstatSync, fstatSync, constants,
} from 'node:fs';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { EngineError } from '../errors.mjs';
import { checkName, toJson, fromJson, checkRange } from './memory.mjs';

export function encodeName(name) {
  const enc = name.replace(/[A-Z]/g, (c) => '+' + c.toLowerCase()).replace(/:/g, '=');
  return enc.length <= 150 ? enc : 'h' + createHash('sha256').update(name, 'utf8').digest('hex');
}

const DIR_MODE = 0o700, FILE_MODE = 0o600;
const NOFOLLOW = constants.O_NOFOLLOW || 0;

/** Write all bytes (writeSync may write fewer than asked). */
function writeAll(fd, bytes, pos) {
  let off = 0;
  while (off < bytes.length) {
    const n = writeSync(fd, bytes, off, bytes.length - off, pos === undefined ? null : pos + off);
    if (!(n > 0)) throw new EngineError('store_io', 'short write', 500);
    off += n;
  }
}
/** Flush a directory entry (best effort: not supported on every platform). */
function syncDir(d) {
  try { const fd = openSync(d, constants.O_RDONLY); try { fsyncSync(fd); } finally { closeSync(fd); } } catch {}
}
/** Refuse a path that is a symbolic link or not a plain directory. */
function plainDir(d) {
  const st = lstatSync(d);
  if (!st.isDirectory()) throw new EngineError('store_corrupt', 'storage path is not a plain directory', 500);
}
/** Read a regular file without following a symbolic link. */
function readPlain(path) {
  const fd = openSync(path, constants.O_RDONLY | NOFOLLOW);
  try {
    if (!fstatSync(fd).isFile()) throw new EngineError('store_corrupt', 'storage path is not a regular file', 500);
    return readFileSync(fd);
  } finally { closeSync(fd); }
}
const record = (text) => {
  let r;
  try { r = fromJson(text); } catch { throw new EngineError('store_corrupt', 'unreadable record file', 500); }
  if (!r || typeof r !== 'object' || Array.isArray(r) || typeof r.id !== 'string' || !('value' in r)) throw new EngineError('store_corrupt', 'malformed record file', 500);
  return r;
};

export function createFileStore(dir) {
  if (typeof dir !== 'string' || !dir) throw new EngineError('bad_dir', 'a directory is required');
  const colRoot = join(dir, 'collections'), strRoot = join(dir, 'streams');
  mkdirSync(colRoot, { recursive: true, mode: DIR_MODE });
  mkdirSync(strRoot, { recursive: true, mode: DIR_MODE });
  plainDir(colRoot); plainDir(strRoot);
  let closed = false;
  const open = () => { if (closed) throw new EngineError('store_closed', 'store is closed', 500); };
  // stream state: { size, good } where good is the byte length of the complete lines
  const streams = new Map();
  const streamPath = (s) => join(strRoot, `s_${encodeName(s)}.jsonl`);

  function scan(stream) {
    const path = streamPath(stream);
    if (!existsSync(path)) return { size: 0, good: 0, total: 0, lines: [] };
    const buf = readPlain(path);
    const end = buf.lastIndexOf(10);
    const good = end + 1;
    const text = buf.subarray(0, good).toString('utf8');
    const lines = good === 0 ? [] : text.slice(0, -1).split('\n');
    return { size: lines.length, good, total: buf.length, lines };
  }
  function state(stream) {
    let st = streams.get(stream);
    if (!st) { const s = scan(stream); st = { size: s.size, good: s.good, total: s.total }; streams.set(stream, st); }
    return st;
  }

  return {
    get(collection, id) {
      open(); checkName(collection, 'collection'); checkName(id);
      const p = join(colRoot, `c_${encodeName(collection)}`, `i_${encodeName(id)}.json`);
      if (!existsSync(join(colRoot, `c_${encodeName(collection)}`))) return null;
      plainDir(join(colRoot, `c_${encodeName(collection)}`));
      let buf;
      try { buf = readPlain(p); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
      const r = record(buf.toString('utf8'));
      if (r.id !== id) throw new EngineError('store_corrupt', 'record file holds a different id', 500);
      return r.value;
    },
    put(collection, id, value) {
      open(); checkName(collection, 'collection'); checkName(id);
      toJson(value); // reject values that are not JSON
      const text = toJson({ id, value });
      const d = join(colRoot, `c_${encodeName(collection)}`);
      mkdirSync(d, { recursive: true, mode: DIR_MODE });
      plainDir(d);
      const final = join(d, `i_${encodeName(id)}.json`);
      const tmp = join(d, `.tmp-${randomBytes(8).toString('hex')}`);
      let fd;
      try {
        fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, FILE_MODE);
        writeAll(fd, Buffer.from(text, 'utf8')); fsyncSync(fd); closeSync(fd); fd = undefined;
        renameSync(tmp, final);
        syncDir(d);
      } catch (e) {
        if (fd !== undefined) try { closeSync(fd); } catch {}
        try { unlinkSync(tmp); } catch {}
        throw e;
      }
    },
    list(collection) {
      open(); checkName(collection, 'collection');
      const d = join(colRoot, `c_${encodeName(collection)}`);
      if (!existsSync(d)) return [];
      plainDir(d);
      const rows = [];
      for (const f of readdirSync(d)) {
        if (!f.startsWith('i_') || !f.endsWith('.json')) continue;
        const r = record(readPlain(join(d, f)).toString('utf8'));
        if (`i_${encodeName(r.id)}.json` !== f) throw new EngineError('store_corrupt', 'record file name does not match its id', 500);
        rows.push(r);
      }
      rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      return rows.map((r) => r.value);
    },
    append(stream, value) {
      open(); checkName(stream, 'stream');
      const line = toJson(value) + '\n';
      const st = state(stream);
      const path = streamPath(stream);
      const created = !existsSync(path);
      const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | NOFOLLOW, FILE_MODE);
      try {
        if (!fstatSync(fd).isFile()) throw new EngineError('store_corrupt', 'storage path is not a regular file', 500);
        // The file must still be what this handle last saw; otherwise another writer changed it and
        // truncating to our offset would destroy its entries.
        if (fstatSync(fd).size !== st.total) {
          streams.delete(stream);
          throw new EngineError('store_conflict', `stream ${stream} was changed by another writer`, 500);
        }
        ftruncateSync(fd, st.good); // drop a truncated tail left by a crash
        const bytes = Buffer.from(line, 'utf8');
        writeAll(fd, bytes, st.good);
        fsyncSync(fd);
        st.good += bytes.length; st.total = st.good;
      } finally { closeSync(fd); }
      if (created) syncDir(strRoot);
      return st.size++;
    },
    read(stream, from = 0, to) {
      open(); checkName(stream, 'stream');
      const s = scan(stream);
      const [f, t] = checkRange(from, to, s.size);
      return s.lines.slice(f, t).map((l) => {
        try { return fromJson(l); } catch { throw new EngineError('store_corrupt', `stream ${stream} has an unreadable line`, 500); }
      });
    },
    size(stream) {
      open(); checkName(stream, 'stream');
      const st = state(stream);
      const path = streamPath(stream);
      if (existsSync(path) && lstatSync(path).size !== st.total) streams.delete(stream); // changed behind our back: rescan
      return state(stream).size;
    },
    /** Report streams whose last line is incomplete (crash during write). */
    verify() {
      open();
      const out = [];
      for (const f of readdirSync(strRoot)) {
        if (!f.startsWith('s_') || !f.endsWith('.jsonl')) continue;
        const buf = readPlain(join(strRoot, f));
        const good = buf.lastIndexOf(10) + 1;
        out.push({ file: f, size: good === 0 ? 0 : buf.subarray(0, good).toString('utf8').split('\n').length - 1, truncatedBytes: buf.length - good });
      }
      return { ok: out.every((s) => s.truncatedBytes === 0), streams: out };
    },
    close() { closed = true; },
  };
}
