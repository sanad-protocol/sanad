// Assessment templates: schema check, hash and the recommended verifier policy. Schema in DESIGN.md section 10.
import { hashOf, policyProblems } from './core.mjs';
import { EngineError } from './errors.mjs';

const ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;
const KINDS = ['auto', 'sitting', 'artifact', 'peer'];
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string' && v.length > 0;
const isLevel = (v) => Number.isInteger(v) && v >= 0 && v <= 5;
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

/** True when v is plain JSON data (strings, finite numbers, booleans, null, arrays, objects) nested at most 12 deep, so that hashing it can never throw. */
function jsonSafe(v, depth = 0) {
  if (depth > 12) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return true;
  if (typeof v === 'number') return Number.isFinite(v);
  if (Array.isArray(v)) return v.every((x) => jsonSafe(x, depth + 1));
  if (isObj(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v))) return Object.keys(v).every((k) => jsonSafe(v[k], depth + 1));
  return false;
}
/** Longest deadline accepted: ten years in hours (larger values overflow date arithmetic). */
const MAX_HOURS = 87600;

function closed(o, required, optional, where, errors) {
  for (const k of Object.keys(o)) if (!required.includes(k) && !optional.includes(k)) errors.push(where + ': unknown member "' + k + '"');
  for (const k of required) if (!(k in o)) errors.push(where + ': missing member "' + k + '"');
}

const POLICY_FIELDS = ['minAttestors', 'requireLive', 'halfLifeMonths', 'minAttestorSittings', 'minAgreement', 'maxInferenceDepth', 'inferenceDecay'];

/** @returns {{ ok: boolean, errors: string[] }} */
export function validateTemplate(t) {
  const errors = [];
  if (!isObj(t)) return { ok: false, errors: ['template must be an object'] };
  closed(t, ['id', 'version', 'title', 'skill', 'levels', 'evidence', 'attestors', 'liveSitting', 'deadlines', 'policy'], ['rubric', 'description', 'levelMap'], 'template', errors);

  if ('id' in t && !(typeof t.id === 'string' && ID_RE.test(t.id))) errors.push('id: must match ' + ID_RE);
  if ('version' in t && !(Number.isInteger(t.version) && t.version >= 1)) errors.push('version: must be an integer of at least 1');
  if ('title' in t && !isStr(t.title)) errors.push('title: must be a non-empty string');
  if ('description' in t && typeof t.description !== 'string') errors.push('description: must be a string');

  if ('skill' in t) {
    const s = t.skill;
    if (!isObj(s)) errors.push('skill: must be an object');
    else {
      closed(s, ['id', 'title'], ['graphHash', 'xwalk'], 'skill', errors);
      if ('id' in s && !(typeof s.id === 'string' && ID_RE.test(s.id))) errors.push('skill.id: must match ' + ID_RE);
      if ('title' in s && !isStr(s.title)) errors.push('skill.title: must be a non-empty string');
      if ('graphHash' in s && !isStr(s.graphHash)) errors.push('skill.graphHash: must be a non-empty string');
      if ('xwalk' in s && !(isObj(s.xwalk) && jsonSafe(s.xwalk))) errors.push('skill.xwalk: must be an object of plain JSON values (finite numbers, nesting up to 12)');
    }
  }

  if ('levels' in t) {
    if (!Array.isArray(t.levels) || t.levels.length === 0) errors.push('levels: must be a non-empty array');
    else {
      const seen = new Set();
      t.levels.forEach((l, i) => {
        const w = 'levels[' + i + ']';
        if (!isObj(l)) { errors.push(w + ': must be an object'); return; }
        closed(l, ['level', 'label'], [], w, errors);
        if ('level' in l) {
          if (!isLevel(l.level)) errors.push(w + '.level: must be an integer from 0 to 5');
          else if (seen.has(l.level)) errors.push(w + '.level: duplicate level ' + l.level);
          else seen.add(l.level);
        }
        if ('label' in l && !isStr(l.label)) errors.push(w + '.label: must be a non-empty string');
      });
    }
  }

  if ('rubric' in t) {
    if (!Array.isArray(t.rubric)) errors.push('rubric: must be an array');
    else {
      const seen = new Set();
      t.rubric.forEach((r, i) => {
        const w = 'rubric[' + i + ']';
        if (!isObj(r)) { errors.push(w + ': must be an object'); return; }
        closed(r, ['id', 'criterion', 'descriptors'], [], w, errors);
        if ('id' in r) {
          if (!(typeof r.id === 'string' && ID_RE.test(r.id))) errors.push(w + '.id: must match ' + ID_RE);
          else if (seen.has(r.id)) errors.push(w + '.id: duplicate id');
          else seen.add(r.id);
        }
        if ('criterion' in r && !isStr(r.criterion)) errors.push(w + '.criterion: must be a non-empty string');
        if ('descriptors' in r) {
          if (!isObj(r.descriptors)) errors.push(w + '.descriptors: must be an object');
          else for (const [k, v] of Object.entries(r.descriptors)) {
            if (!/^[0-5]$/.test(k)) errors.push(w + '.descriptors: key "' + k + '" is not a level from 0 to 5');
            if (typeof v !== 'string') errors.push(w + '.descriptors.' + k + ': must be a string');
          }
        }
      });
    }
  }

  let hasSitting = false;
  if ('evidence' in t) {
    if (!Array.isArray(t.evidence) || t.evidence.length === 0) errors.push('evidence: must be a non-empty array');
    else {
      const seen = new Set();
      t.evidence.forEach((e, i) => {
        const w = 'evidence[' + i + ']';
        if (!isObj(e)) { errors.push(w + ': must be an object'); return; }
        closed(e, ['key', 'kind', 'summary'], ['live', 'minutes'], w, errors);
        if ('key' in e) {
          if (typeof e.key === 'string' && /^a\d{2,}$/.test(e.key)) errors.push(w + '.key: "' + e.key + '" looks like an attestation id (a01, a02, ...) and would collide with one');
          else if (!(typeof e.key === 'string' && ID_RE.test(e.key))) errors.push(w + '.key: must match ' + ID_RE);
          else if (seen.has(e.key)) errors.push(w + '.key: duplicate key');
          else seen.add(e.key);
        }
        if ('kind' in e) {
          if (!KINDS.includes(e.kind)) errors.push(w + '.kind: must be one of ' + KINDS.join(', '));
          else if (e.kind === 'sitting') hasSitting = true;
        }
        if ('summary' in e && typeof e.summary !== 'string') errors.push(w + '.summary: must be a string');
        if ('live' in e && typeof e.live !== 'boolean') errors.push(w + '.live: must be true or false');
        if ('minutes' in e && !(isNum(e.minutes) && e.minutes > 0)) errors.push(w + '.minutes: must be a positive number');
      });
    }
  }

  if ('attestors' in t) {
    const a = t.attestors;
    if (!isObj(a)) errors.push('attestors: must be an object');
    else {
      closed(a, ['min', 'max', 'roles'], [], 'attestors', errors);
      const okMin = Number.isInteger(a.min) && a.min >= 1, okMax = Number.isInteger(a.max) && a.max >= 1;
      if ('min' in a && !okMin) errors.push('attestors.min: must be an integer of at least 1');
      if ('max' in a && !okMax) errors.push('attestors.max: must be an integer of at least 1');
      if (okMin && okMax && a.min > a.max) errors.push('attestors: min must not exceed max');
      if ('roles' in a) {
        if (!Array.isArray(a.roles) || a.roles.length === 0) errors.push('attestors.roles: must be a non-empty array');
        else {
          if (!a.roles.every(isStr)) errors.push('attestors.roles: every role must be a non-empty string');
          if (new Set(a.roles).size !== a.roles.length) errors.push('attestors.roles: duplicate role');
        }
      }
    }
  }

  if ('liveSitting' in t) {
    if (typeof t.liveSitting !== 'boolean') errors.push('liveSitting: must be true or false');
    else if (t.liveSitting && Array.isArray(t.evidence) && !hasSitting) errors.push('liveSitting: true needs at least one evidence item of kind sitting');
  }

  if ('deadlines' in t) {
    const d = t.deadlines;
    if (!isObj(d)) errors.push('deadlines: must be an object');
    else {
      closed(d, ['commitHours', 'revealHours'], [], 'deadlines', errors);
      for (const k of ['commitHours', 'revealHours']) if (k in d && !(isNum(d[k]) && d[k] > 0 && d[k] <= MAX_HOURS)) errors.push('deadlines.' + k + ': must be a positive number of at most ' + MAX_HOURS);
    }
  }

  if ('levelMap' in t) {
    if (!isObj(t.levelMap)) errors.push('levelMap: must be an object');
    else for (const [k, v] of Object.entries(t.levelMap)) {
      if (!/^[A-Za-z0-9]{1,16}$/.test(k)) errors.push('levelMap: key "' + k + '" must be 1 to 16 letters or digits (it is written into the nonce)');
      if (k in Object.prototype) errors.push('levelMap: key "' + k + '" is reserved');
      if (!isLevel(v)) errors.push('levelMap.' + k + ': must be an integer from 0 to 5');
    }
  }

  if ('policy' in t) {
    const p = t.policy;
    if (!isObj(p)) errors.push('policy: must be an object');
    else {
      closed(p, ['id', ...POLICY_FIELDS], [], 'policy', errors);
      if ('id' in p && !(typeof p.id === 'string' && ID_RE.test(p.id))) errors.push('policy.id: must match ' + ID_RE);
      const num = (k, ok, what) => { if (k in p && !(isNum(p[k]) && ok(p[k]))) errors.push('policy.' + k + ': must be ' + what); };
      num('minAttestors', (v) => Number.isInteger(v) && v >= 1, 'an integer of at least 1');
      if ('requireLive' in p && typeof p.requireLive !== 'boolean') errors.push('policy.requireLive: must be true or false');
      num('halfLifeMonths', (v) => v > 0, 'a number above 0');
      num('minAttestorSittings', (v) => v >= 0, 'a number of at least 0');
      num('minAgreement', (v) => v >= 0 && v <= 1, 'a number from 0 to 1');
      num('maxInferenceDepth', (v) => Number.isInteger(v) && v >= 0, 'an integer of at least 0');
      num('inferenceDecay', (v) => v >= 0 && v <= 1, 'a number from 0 to 1');
    }
  }
  return { ok: errors.length === 0, errors };
}

/** Throws EngineError('bad_template') listing every problem. Returns the template. */
export function assertTemplate(t) {
  const r = validateTemplate(t);
  if (!r.ok) throw new EngineError('bad_template', r.errors.join('; '), 400);
  return t;
}

export function templateHash(t) { return hashOf(t); }

/** The core Policy (eight fields) recommended by the template, for the given evaluation day. */
export function policyFromTemplate(t, asOf) {
  const p = t.policy;
  return {
    minAttestors: p.minAttestors, requireLive: p.requireLive, halfLifeMonths: p.halfLifeMonths, minAttestorSittings: p.minAttestorSittings,
    minAgreement: p.minAgreement, maxInferenceDepth: p.maxInferenceDepth, inferenceDecay: p.inferenceDecay, asOf,
  };
}

const NATIVE_NONCE = /^nm-([A-Za-z0-9]{1,16})-[A-Za-z0-9_-]{16,}$/;
/**
 * levelMap (optional template member): host-native mark label -> Sanad level 0..5. It is a convention, not a second source of truth:
 * the attestor may write the native mark into the nonce (nm-<native>-<random>), which stays hidden until the reveal, so blind commit is unchanged.
 * When a template has a levelMap and a revealed nonce carries a native mark, the engine requires levelMap[native] to equal the revealed level.
 * The mapping itself is not applied by the engine to any mark and never reveals or changes one.
 */
export function levelFromNative(levelMap, native) {
  if (!levelMap || typeof levelMap !== 'object' || !Object.hasOwn(levelMap, String(native))) throw new EngineError('native_unknown', 'the levelMap has no native mark ' + native, 400);
  return levelMap[String(native)];
}
/** nm-<native>-<random>, with the random part at least 16 characters. */
export function nonceWithNative(native, random) {
  if (!/^[A-Za-z0-9]{1,16}$/.test(String(native))) throw new EngineError('bad_nonce', 'native mark must be 1 to 16 letters or digits');
  return 'nm-' + native + '-' + random;
}
/** The native mark carried by a nonce, or null. */
export function nativeOfNonce(nonce) {
  const m = typeof nonce === 'string' ? NATIVE_NONCE.exec(nonce) : null;
  return m ? m[1] : null;
}

/** Every field of a verifier policy (the seven fields and asOf) is required and range-checked. Returns the problems; empty means usable. */
export function validatePolicy(p) { return policyProblems(p); }
