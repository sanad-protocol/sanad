// I-JSON edge cases (RFC 7493) for data that will be hashed: no lone surrogates, no integers beyond 2^53, no non-finite numbers, bounded nesting.
// A raw scan runs before JSON.parse (depth and number tokens, which JSON.parse would silently round), a value check after it.
import { EngineError } from './errors.mjs';

export const MAX_DEPTH = 64;
const bad = (code, message) => new EngineError(code, message, 400);
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** Scans JSON text without parsing it: nesting depth, and number tokens that JSON.parse would round or turn into Infinity. Throws EngineError. */
export function scanJsonText(text, { maxDepth = MAX_DEPTH } = {}) {
  let depth = 0, inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) { if (c === 92) i++; else if (c === 34) inStr = false; continue; }
    if (c === 34) { inStr = true; continue; }
    if (c === 91 || c === 123) { if (++depth > maxDepth) throw bad('too_deep', 'JSON nesting is deeper than ' + maxDepth); continue; }
    if (c === 93 || c === 125) { depth--; continue; }
    if (c === 45 || (c >= 48 && c <= 57)) {
      let j = i + 1;
      while (j < text.length) { const d = text.charCodeAt(j); if ((d >= 48 && d <= 57) || d === 46 || d === 101 || d === 69 || d === 43 || d === 45) j++; else break; }
      const tok = text.slice(i, j), n = Number(tok);
      if (!Number.isFinite(n)) throw bad('bad_number', 'a number is not finite: ' + tok.slice(0, 20));
      if (/^-?\d+$/.test(tok) && !Number.isSafeInteger(n)) throw bad('bad_number', 'an integer beyond 2^53 cannot be represented exactly: ' + tok.slice(0, 20));
      i = j - 1;
    }
  }
}

/** Checks an already parsed value. Throws EngineError. */
export function checkIJson(v, { maxDepth = MAX_DEPTH } = {}) {
  const walk = (x, d) => {
    if (d > maxDepth) throw bad('too_deep', 'nesting is deeper than ' + maxDepth);
    if (typeof x === 'string') { if (LONE.test(x)) throw bad('bad_string', 'a string holds a lone surrogate'); return; }
    if (typeof x === 'number') { if (!Number.isFinite(x)) throw bad('bad_number', 'a number is not finite'); if (Number.isInteger(x) && !Number.isSafeInteger(x)) throw bad('bad_number', 'an integer beyond 2^53'); return; }
    if (x === null || typeof x === 'boolean') return;
    if (Array.isArray(x)) { for (const y of x) walk(y, d + 1); return; }
    if (typeof x === 'object') { for (const k of Object.keys(x)) { if (LONE.test(k)) throw bad('bad_string', 'a key holds a lone surrogate'); walk(x[k], d + 1); } return; }
    throw bad('bad_json', 'a value of type ' + typeof x + ' is not JSON');
  };
  walk(v, 0);
  return v;
}
