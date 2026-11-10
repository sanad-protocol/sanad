// In-memory storage adapter. Also holds the checks shared by every adapter.
import { EngineError } from '../errors.mjs';

const NAME = /^[A-Za-z0-9._:-]{1,200}$/;

/** Throw EngineError('bad_id') unless `name` is a legal id, collection or stream name. */
export function checkName(name, what = 'id') {
  if (typeof name !== 'string' || !NAME.test(name) || name === '.' || name === '..') {
    throw new EngineError('bad_id', `invalid ${what}: must match ${NAME}`);
  }
  return name;
}

/** Serialise a value to JSON text; only JSON-serialisable values are accepted. */
export function toJson(value) {
  let text;
  try { text = JSON.stringify(value); } catch (e) { throw new EngineError('bad_value', 'value is not JSON-serialisable'); }
  if (typeof text !== 'string') throw new EngineError('bad_value', 'value is not JSON-serialisable');
  return text;
}

export const fromJson = (text) => JSON.parse(text);

export function checkRange(from, to, size) {
  const f = from, t = to === undefined ? size : to;
  if (!Number.isInteger(f) || !Number.isInteger(t) || f < 0 || t > size || f > t) {
    throw new EngineError('bad_range', `invalid range [${from}, ${to}) for size ${size}`);
  }
  return [f, t];
}

export function createMemoryStore() {
  const cols = new Map();
  const streams = new Map();
  let closed = false;
  const open = () => { if (closed) throw new EngineError('store_closed', 'store is closed', 500); };
  return {
    get(collection, id) {
      open(); checkName(collection, 'collection'); checkName(id);
      const t = cols.get(collection)?.get(id);
      return t === undefined ? null : fromJson(t);
    },
    put(collection, id, value) {
      open(); checkName(collection, 'collection'); checkName(id);
      const t = toJson(value);
      if (!cols.has(collection)) cols.set(collection, new Map());
      cols.get(collection).set(id, t);
    },
    list(collection) {
      open(); checkName(collection, 'collection');
      const m = cols.get(collection);
      if (!m) return [];
      return [...m.keys()].sort().map((k) => fromJson(m.get(k)));
    },
    append(stream, value) {
      open(); checkName(stream, 'stream');
      const t = toJson(value);
      if (!streams.has(stream)) streams.set(stream, []);
      const a = streams.get(stream);
      a.push(t);
      return a.length - 1;
    },
    read(stream, from = 0, to) {
      open(); checkName(stream, 'stream');
      const a = streams.get(stream) || [];
      const [f, t] = checkRange(from, to, a.length);
      return a.slice(f, t).map(fromJson);
    },
    size(stream) {
      open(); checkName(stream, 'stream');
      return (streams.get(stream) || []).length;
    },
    close() { closed = true; },
  };
}
