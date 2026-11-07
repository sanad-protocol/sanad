// Canonical JSON: keys sorted (by UTF-16 code unit order), no whitespace, UTF-8 when hashed; undefined properties are dropped; non-finite numbers are refused.
// Two machines that read the same data always get the same bytes, so the same hash.
import { sha256Hex } from './sha256';

export function canonical(v: unknown): string {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'string': return JSON.stringify(v);
    case 'boolean': return v ? 'true' : 'false';
    case 'number': if (!Number.isFinite(v)) throw new Error('canonical JSON refuses NaN and Infinity'); return JSON.stringify(v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : canonical(x))).join(',') + ']';
      const o = v as Record<string, unknown>;
      return '{' + Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(o[k])).join(',') + '}';
    }
    default: throw new Error('canonical JSON cannot hold a ' + typeof v);
  }
}
export const hashOf = (v: unknown) => sha256Hex(canonical(v));
