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
  fsyncSync, writeSync, ftruncateSync, unlinkSync, constants,
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

export function createFileStore(dir) {
  if (typeof dir !== 'string' || !dir) throw new EngineError('bad_dir', 'a directory is required');
  const colRoot = join(dir, 'collections'), strRoot = join(dir, 'streams');
  mkdirSync(colRoot, { recursive: true, mode: DIR_MODE });
  mkdirSync(strRoot, { recursive: true, mode: DIR_MODE });
  let closed = false;
  const open = () => { if (closed) throw new EngineError('store_closed', 'store is closed', 500); };
  // stream state: { size, good } where good is the byte length of the complete lines
  const streams = new Map();
  const streamPath = (s) => join(strRoot, `s_${encodeName(s)}.jsonl`);

  function scan(stream) {
    const path = streamPath(stream);
    if (!existsSync(path)) return { size: 0, good: 0, total: 0, lines: [] };
    const buf = readFileSync(path);
    const end = buf.lastIndexOf(10);
    const good = end + 1;
    const text = buf.subarray(0, good).toString('utf8');
    const lines = good === 0 ? [] : text.slice(0, -1).split('\n');
    return { size: lines.length, good, total: buf.length, lines };
  }
  function state(stream) {
    let st = streams.get(stream);
    if (!st) { const s = scan(stream); st = { size: s.size, good: s.good }; streams.set(stream, st); }
    return st;
  }

  return {
    get(collection, id) {
      open(); checkName(collection, 'collection'); checkName(id);
      const p = join(colRoot, `c_${encodeName(collection)}`, `i_${encodeName(id)}.json`);
      if (!existsSync(p)) return null;
      return fromJson(readFileSync(p, 'utf8')).value;
    },
    put(collection, id, value) {
      open(); checkName(collection, 'collection'); checkName(id);
      toJson(value); // reject values that are not JSON
      const text = toJson({ id, value });
      const d = join(colRoot, `c_${encodeName(collection)}`);
      mkdirSync(d, { recursive: true, mode: DIR_MODE });
      const final = join(d, `i_${encodeName(id)}.json`);
      const tmp = join(d, `.tmp-${randomBytes(8).toString('hex')}`);
      let fd;
      try {
        fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, FILE_MODE);
        writeSync(fd, text); fsyncSync(fd); closeSync(fd); fd = undefined;
        renameSync(tmp, final);
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
      const rows = [];
      for (const f of readdirSync(d)) {
        if (!f.startsWith('i_') || !f.endsWith('.json')) continue;
        rows.push(fromJson(readFileSync(join(d, f), 'utf8')));
      }
      rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      return rows.map((r) => r.value);
    },
    append(stream, value) {
      open(); checkName(stream, 'stream');
      const line = toJson(value) + '\n';
      const st = state(stream);
      const path = streamPath(stream);
      const fd = openSync(path, constants.O_RDWR | constants.O_CREAT, FILE_MODE);
      try {
        ftruncateSync(fd, st.good); // drop a truncated tail left by a crash
        const bytes = Buffer.from(line, 'utf8');
        writeSync(fd, bytes, 0, bytes.length, st.good);
        fsyncSync(fd);
        st.good += bytes.length;
      } finally { closeSync(fd); }
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
    size(stream) { open(); checkName(stream, 'stream'); return state(stream).size; },
    /** Report streams whose last line is incomplete (crash during write). */
    verify() {
      open();
      const out = [];
      for (const f of readdirSync(strRoot)) {
        if (!f.startsWith('s_') || !f.endsWith('.jsonl')) continue;
        const buf = readFileSync(join(strRoot, f));
        const good = buf.lastIndexOf(10) + 1;
        out.push({ file: f, size: good === 0 ? 0 : buf.subarray(0, good).toString('utf8').split('\n').length - 1, truncatedBytes: buf.length - good });
      }
      return { ok: out.every((s) => s.truncatedBytes === 0), streams: out };
    },
    close() { closed = true; },
  };
}
