// Sanad engine 0.2.0, algorithm sanad-0.1 (Apache-2.0). Generated from engine/src by engine/build.mjs.
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// engine/src/core.mjs
var core_exports = {};
__export(core_exports, {
  CAP: () => CAP,
  DEFAULT_POLICY: () => DEFAULT_POLICY,
  QUALIFYING: () => QUALIFYING,
  REPLAY: () => REPLAY,
  SAMPLE_NAMES: () => SAMPLE_NAMES,
  SAMPLE_SKILL: () => SAMPLE_SKILL,
  SAMPLE_TAMPER: () => SAMPLE_TAMPER,
  SANAD_VERSION: () => SANAD_VERSION,
  WEIGHT: () => WEIGHT,
  applyTamper: () => applyTamper,
  assertPolicy: () => assertPolicy,
  attestationHashOf: () => attestationHashOf,
  attestationPayload: () => attestationPayload,
  canonical: () => canonical,
  checkIntegrity: () => checkIntegrity,
  commitOf: () => commitOf,
  commitPayload: () => commitPayload,
  dayNumber: () => dayNumber,
  evidenceHash: () => evidenceHash,
  explainInference: () => explainInference,
  graphFromEdges: () => graphFromEdges,
  hashOf: () => hashOf,
  infer: () => infer,
  policyProblems: () => policyProblems,
  recognise: () => recognise,
  sampleCredential: () => sampleCredential,
  sealAttestations: () => sealAttestations,
  sealCredential: () => sealCredential,
  sealEvidence: () => sealEvidence,
  sha256Hex: () => sha256Hex,
  sha256HexWebCrypto: () => sha256HexWebCrypto
});

// reference/dist/sanad-reference.mjs
var SANAD_VERSION = "sanad-0.1";
var DEFAULT_POLICY = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 3, minAgreement: 0.6, maxInferenceDepth: 2, inferenceDecay: 0.7, asOf: "2026-11-07" };
var K = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var rotr = (x, n) => x >>> n | x << 32 - n;
function sha256Bytes(data) {
  const h = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]);
  const bitLen = data.length * 8;
  const padded = new Uint8Array(data.length + 9 + 63 >> 6 << 6);
  padded.set(data);
  padded[data.length] = 128;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3, s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
      w[i] = w[i - 16] + s0 + w[i - 7] + s1 >>> 0;
    }
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = e & f ^ ~e & g, t1 = hh + S1 + ch + K[i] + w[i] >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = a & b ^ a & c ^ b & c, t2 = S0 + mj >>> 0;
      hh = g;
      g = f;
      f = e;
      e = d + t1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = t1 + t2 >>> 0;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
  const out = new Uint8Array(32);
  const o = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) o.setUint32(i * 4, h[i]);
  return out;
}
var HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
var toHex = (b) => {
  let s = "";
  for (const x of b) s += HEX[x];
  return s;
};
var sha256Hex = (text) => toHex(sha256Bytes(new TextEncoder().encode(text)));
async function sha256HexWebCrypto(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return toHex(new Uint8Array(buf));
}
function canonical(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "string":
      return JSON.stringify(v);
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new Error("canonical JSON refuses NaN and Infinity");
      return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map((x) => x === void 0 ? "null" : canonical(x)).join(",") + "]";
      const o = v;
      return "{" + Object.keys(o).filter((k) => o[k] !== void 0).sort().map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
    }
    default:
      throw new Error("canonical JSON cannot hold a " + typeof v);
  }
}
var hashOf = (v) => sha256Hex(canonical(v));
var evidenceHash = (e) => hashOf(e.body);
var commitPayload = (a) => ({ attestor: a.attestor, evidence: a.evidence, level: a.level, nonce: a.nonce });
var attestationPayload = (a) => ({
  id: a.id,
  attestor: a.attestor,
  evidence: a.evidence,
  level: a.level,
  role: a.role,
  conflictDeclared: a.conflictDeclared,
  date: a.date,
  commit: a.commit,
  nonce: a.nonce,
  prev: a.prev
});
var commitOf = (a) => hashOf(commitPayload(a));
var attestationHashOf = (a) => hashOf(attestationPayload(a));
function sealEvidence(d) {
  return { ...d, hash: evidenceHash(d) };
}
function sealAttestations(drafts) {
  const out = [];
  let prev = "GENESIS";
  for (const d of [...drafts].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) {
    const base = { id: d.id, attestor: d.attestor, evidence: d.evidence, level: d.level, role: d.role ?? "examiner", conflictDeclared: d.conflictDeclared ?? false, date: d.date, nonce: d.nonce ?? "n-" + d.id, prev };
    const commit = commitOf(base);
    const hash = attestationHashOf({ ...base, commit });
    out.push({ ...base, commit, hash, signature: "unsigned-v0.1:" + hash });
    prev = hash;
  }
  return out;
}
function sealCredential(c) {
  return { skill: c.skill, claimedLevel: c.claimedLevel, subject: c.subject, evidence: c.evidence.map(sealEvidence), attestations: sealAttestations(c.attestations), attestors: c.attestors };
}
function setPath(o, path, value) {
  const parts = path.split(".");
  let cur = o;
  for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]] = { ...cur[parts[i]] };
  cur[parts[parts.length - 1]] = value;
}
function applyTamper(c, ops) {
  const out = JSON.parse(JSON.stringify(c));
  for (const op of ops) {
    const target = "attestation" in op ? out.attestations.find((a) => a.id === op.attestation) : out.evidence.find((e) => e.id === op.evidence);
    if (!target) throw new Error("tamper target not found");
    for (const [k, v] of Object.entries(op.set)) setPath(target, k, v);
  }
  return out;
}
var WEIGHT = { auto: 0.25, sitting: 0.6, artifact: 0.3, peer: 0.15 };
var CAP = { auto: 3, sitting: 5, artifact: 4, peer: 3 };
var QUALIFYING = ["sitting", "artifact"];
var REPLAY = "replay";
var MONTH_DAYS = 30.4375;
var KINDS = ["auto", "sitting", "artifact", "peer"];
var byId = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
var round3 = (x) => Math.round(x * 1e3) / 1e3;
var lowerMedian = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor((s.length - 1) / 2)];
};
var uniq = (xs) => [...new Set(xs)];
var f2 = (x) => (Math.round(x * 100) / 100).toString();
function dayNumber(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return NaN;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3]);
  const d = new Date(t);
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? t / 864e5 : NaN;
}
var isNum = (v) => typeof v === "number" && Number.isFinite(v);
function policyProblems(p) {
  const why = [];
  if (p === null || typeof p !== "object" || Array.isArray(p)) return ["policy must be an object"];
  const o = p;
  if (!(isNum(o.minAttestors) && Number.isInteger(o.minAttestors) && o.minAttestors >= 1)) why.push("minAttestors must be an integer of at least 1");
  if (typeof o.requireLive !== "boolean") why.push("requireLive must be true or false");
  if (!(isNum(o.halfLifeMonths) && o.halfLifeMonths > 0)) why.push("halfLifeMonths must be a number above 0");
  if (!(isNum(o.minAttestorSittings) && o.minAttestorSittings >= 0)) why.push("minAttestorSittings must be a number of at least 0");
  if (!(isNum(o.minAgreement) && o.minAgreement >= 0 && o.minAgreement <= 1)) why.push("minAgreement must be a number from 0 to 1");
  if (!(isNum(o.maxInferenceDepth) && Number.isInteger(o.maxInferenceDepth) && o.maxInferenceDepth >= 0)) why.push("maxInferenceDepth must be an integer of at least 0");
  if (!(isNum(o.inferenceDecay) && o.inferenceDecay >= 0 && o.inferenceDecay <= 1)) why.push("inferenceDecay must be a number from 0 to 1");
  if (typeof o.asOf !== "string" || Number.isNaN(dayNumber(o.asOf))) why.push("asOf must be an ISO date yyyy-mm-dd");
  return why;
}
function assertPolicy(p) {
  const w = policyProblems(p);
  if (w.length) throw new RangeError(w.join("; "));
}
var levelOk = (v) => Number.isInteger(v) && v >= 0 && v <= 5;
function checkIntegrity(cred, opts = {}) {
  const evs = [...cred.evidence].sort(byId), atts = [...cred.attestations].sort(byId);
  const evidence = evs.map((e) => {
    const why = [];
    if (!KINDS.includes(e.kind)) why.push('unknown kind "' + e.kind + '"');
    if (Number.isNaN(dayNumber(e.date))) why.push("date is not a valid yyyy-mm-dd");
    let h = "";
    try {
      h = hashOf(e.body);
    } catch {
      why.push("body cannot be canonicalised");
    }
    if (h && h !== e.hash) why.push("its content no longer matches its hash (changed after sealing)");
    if (e.kind === "auto" && !levelOk(e.body?.autoLevel)) why.push("an automatic record needs autoLevel 0..5 in its body");
    return { id: e.id, ok: why.length === 0, reason: why.join("; ") };
  });
  const evOk = new Map(evidence.map((x) => [x.id, x.ok]));
  const attestations = atts.map((a, i) => {
    const why = [];
    if (!levelOk(a.level)) why.push("level is not 0..5");
    else {
      if (attestationHashOf(a) !== a.hash) why.push("its content no longer matches its hash (changed after sealing)");
      if (commitOf(a) !== a.commit) why.push("the revealed mark does not match the commitment made before marking");
    }
    if (opts.verifySignature) {
      let good = false;
      try {
        good = opts.verifySignature(a) === true;
      } catch {
        good = false;
      }
      if (!good) why.push("the signature does not verify");
    }
    const expectPrev = i === 0 ? "GENESIS" : atts[i - 1].hash;
    if (a.prev !== expectPrev) why.push("chain break: it does not link to the attestation before it");
    const dup = atts.slice(0, i).find((x) => x.attestor === a.attestor && x.evidence === a.evidence);
    if (dup) why.push("duplicate mark: " + a.attestor + " already has attestation " + dup.id + " on this evidence item (only the first counts)");
    if (!evOk.has(a.evidence)) why.push('it attests evidence "' + a.evidence + '" that is not in the credential');
    else if (!evOk.get(a.evidence)) why.push('it attests evidence "' + a.evidence + '" that failed integrity');
    if (Number.isNaN(dayNumber(a.date))) why.push("date is not a valid yyyy-mm-dd");
    return { id: a.id, ok: why.length === 0, reason: why.join("; ") };
  });
  return { evidence, attestations };
}
function recognise(cred, policy, opts = {}) {
  assertPolicy(policy);
  const asOf = dayNumber(policy.asOf);
  const minAtt = Math.max(1, Math.floor(policy.minAttestors));
  const steps = [];
  const dropped = [];
  const evs = [...cred.evidence].sort(byId), atts = [...cred.attestations].sort(byId);
  const integ = checkIntegrity(cred, opts);
  const evBad = new Map(integ.evidence.filter((x) => !x.ok).map((x) => [x.id, x.reason]));
  const attBad = new Map(integ.attestations.filter((x) => !x.ok).map((x) => [x.id, x.reason]));
  steps.push({ rule: "R1", summary: `Checked ${evs.length} evidence item(s) and ${atts.length} attestation(s): every hash, every reveal against its commitment, and the chain. ${evBad.size + attBad.size} failed.`, inputs: [...evs.map((e) => e.id), ...atts.map((a) => a.id)], effect: evBad.size + attBad.size ? "failed items are ignored" : "nothing ignored" });
  for (const e of evs) if (evBad.has(e.id)) {
    dropped.push({ id: e.id, rule: "R1", reason: evBad.get(e.id) });
    steps.push({ rule: "R1", summary: `Evidence ${e.id} was ignored: ${evBad.get(e.id)}.`, inputs: [e.id], effect: "dropped" });
  }
  for (const a of atts) if (attBad.has(a.id)) {
    dropped.push({ id: a.id, rule: "R1", reason: attBad.get(a.id) });
    steps.push({ rule: "R1", summary: `Attestation ${a.id} (by ${a.attestor}) was ignored: ${attBad.get(a.id)}.`, inputs: [a.id, a.attestor], effect: "dropped" });
  }
  const age = /* @__PURE__ */ new Map();
  const evAdm = /* @__PURE__ */ new Map();
  for (const e of evs) {
    if (evBad.has(e.id)) continue;
    const m = (asOf - dayNumber(e.date)) / MONTH_DAYS;
    age.set(e.id, m);
    if (m < 0) {
      dropped.push({ id: e.id, rule: "R2", reason: "dated after the evaluation day" });
      steps.push({ rule: "R2", summary: `Evidence ${e.id} was ignored: it is dated after the evaluation day ${policy.asOf}.`, inputs: [e.id], effect: "dropped" });
      continue;
    }
    if (m > 4 * policy.halfLifeMonths) {
      dropped.push({ id: e.id, rule: "R2", reason: `older than 4 half-lives (${f2(m)} months; half-life ${policy.halfLifeMonths})` });
      steps.push({ rule: "R2", summary: `Evidence ${e.id} was ignored: ${f2(m)} months old, more than 4 half-lives (${policy.halfLifeMonths} months each).`, inputs: [e.id], effect: "dropped" });
      continue;
    }
    evAdm.set(e.id, e);
  }
  const items = [];
  for (const e of evAdm.values()) if (e.kind === "auto") items.push({ att: null, attestor: REPLAY, level: e.body.autoLevel, evidence: e });
  for (const a of atts) {
    if (attBad.has(a.id)) continue;
    const e = evAdm.get(a.evidence);
    if (!e) continue;
    if (e.kind === "auto") continue;
    const st = cred.attestors[a.attestor] ?? { sittings: 0, agreement: 0 };
    let why = "";
    if (opts.allowAttestor && !opts.allowAttestor(a.attestor)) why = "the attestor is not on the verifier's allow-list";
    else if (a.conflictDeclared) why = "a conflict of interest was declared";
    else if (st.sittings < policy.minAttestorSittings) why = `only ${st.sittings} sitting(s), policy needs ${policy.minAttestorSittings}`;
    else if (st.agreement < policy.minAgreement) why = `agreement with other examiners is ${f2(st.agreement)}, policy needs ${f2(policy.minAgreement)}`;
    if (why) {
      dropped.push({ id: a.id, rule: "R2", reason: why });
      steps.push({ rule: "R2", summary: `Attestor ${a.attestor} (attestation ${a.id}) was ignored: ${why}.`, inputs: [a.id, a.attestor], effect: "dropped" });
      continue;
    }
    items.push({ att: a, attestor: a.attestor, level: a.level, evidence: e });
  }
  steps.push({ rule: "R2", summary: `${items.length} attestation(s) and automatic record(s) are admissible on ${new Set(items.map((i) => i.evidence.id)).size} evidence item(s).`, inputs: items.map((i) => i.att?.id ?? i.evidence.id), effect: "these are used" });
  const factor = /* @__PURE__ */ new Map();
  const evLevel = /* @__PURE__ */ new Map();
  const evSpread = /* @__PURE__ */ new Map();
  const evItems = /* @__PURE__ */ new Map();
  for (const it of items) {
    const l = evItems.get(it.evidence.id) ?? [];
    l.push(it);
    evItems.set(it.evidence.id, l);
  }
  for (const e of evs) {
    const its = evItems.get(e.id);
    if (!its) continue;
    const m = age.get(e.id);
    const a = Math.pow(0.5, m / policy.halfLifeMonths);
    factor.set(e.id, a);
    steps.push({ rule: "R3", summary: `Evidence ${e.id} is ${f2(m)} month(s) old: age factor ${a.toFixed(3)} (half-life ${policy.halfLifeMonths} months).`, inputs: [e.id], effect: `weight x ${a.toFixed(3)}` });
    const lv = its.map((i) => i.level);
    const med = lowerMedian(lv);
    const cap = CAP[e.kind];
    const lvl = Math.min(med, cap);
    evLevel.set(e.id, lvl);
    evSpread.set(e.id, Math.max(...lv) - Math.min(...lv));
    steps.push({ rule: "R4", summary: `Evidence ${e.id} (${e.kind}): levels ${JSON.stringify([...lv].sort((x, y) => x - y))}, lower median ${med}${med > cap ? `, capped at ${cap} for ${e.kind} evidence` : ""} -> level ${lvl}.`, inputs: [e.id, ...its.map((i) => i.att?.id ?? e.id)], effect: `evidence level ${lvl}` });
  }
  for (const e of evAdm.values()) if (!evItems.has(e.id)) steps.push({ rule: "R4", summary: `Evidence ${e.id} has no admissible attestation, so it does not count.`, inputs: [e.id], effect: "no level" });
  const qual = [...evLevel.keys()].filter((id) => QUALIFYING.includes(evAdm.get(id).kind));
  const attestors = uniq(qual.flatMap((id) => evItems.get(id).map((i) => i.attestor))).sort();
  const live = qual.some((id) => evAdm.get(id).kind === "sitting");
  const reasons = [];
  if (!qual.length) reasons.push("there is no live-sitting or artifact evidence with an admissible attestor");
  if (attestors.length < minAtt) reasons.push(`${attestors.length} independent attestor(s) count, policy needs ${minAtt}`);
  if (policy.requireLive && !live) reasons.push("policy requires a live sitting and none is admissible");
  const independent = reasons.length === 0;
  const hasEvidence = evLevel.size > 0;
  steps.push({ rule: "R5", summary: independent ? `${attestors.length} distinct admissible attestor(s) (${attestors.join(", ")}); policy needs ${minAtt}${policy.requireLive ? " and a live sitting, which is present" : ""}. Independence is met.` : `Independence is not met: ${reasons.join("; ")}.`, inputs: attestors, effect: independent ? "status can be recognised" : "status is provisional" });
  const attestedLevel = qual.length ? Math.min(cred.claimedLevel, lowerMedian(qual.map((id) => evLevel.get(id)))) : null;
  const weak = [...evLevel.keys()].filter((id) => !QUALIFYING.includes(evAdm.get(id).kind)).map((id) => evLevel.get(id));
  let status;
  let level;
  if (!hasEvidence) {
    status = "not-recognised";
    level = 0;
  } else if (independent) {
    status = "recognised";
    level = attestedLevel;
  } else {
    status = "provisional";
    level = Math.min(cred.claimedLevel, weak.length ? Math.max(...weak) : 0);
  }
  steps.push({ rule: "R6", summary: !hasEvidence ? "There is no admissible evidence: nothing is recognised." : independent ? `Recognised level = the lower of the claim (${cred.claimedLevel}) and the lower median of the live-sitting and artifact evidence levels (${JSON.stringify(qual.map((id) => evLevel.get(id)).sort((x, y) => x - y))}) = ${level}.` : `Provisional: the level is limited to the best automatic or peer evidence (${weak.length ? Math.max(...weak) : "none"}), so it is ${level}.${attestedLevel !== null ? ` If the policy were met it would be ${attestedLevel}.` : ""}`, inputs: qual, effect: `level ${level}, ${status}` });
  let miss = 1;
  for (const it of items) {
    const e = it.evidence;
    const f = (evSpread.get(e.id) ?? 0) <= 1 ? 1 : 0.5;
    miss *= 1 - WEIGHT[e.kind] * factor.get(e.id) * f;
  }
  const confidence = hasEvidence ? round3(1 - miss) : 0;
  const halved = [...evSpread.entries()].filter(([, s]) => s > 1).map(([id]) => id);
  steps.push({ rule: "R7", summary: hasEvidence ? `Confidence = 1 - the product of (1 - weight x age factor x agreement factor) over ${items.length} item(s) = ${confidence.toFixed(3)}.${halved.length ? ` Attestors of ${halved.join(", ")} disagree by more than one level, so their weight was halved.` : ""}` : "No admissible evidence: confidence 0.", inputs: items.map((i) => i.att?.id ?? i.evidence.id), effect: `confidence ${confidence.toFixed(3)}` });
  return {
    version: SANAD_VERSION,
    skill: cred.skill,
    claimedLevel: cred.claimedLevel,
    status,
    level,
    attestedLevel,
    confidence,
    explanation: steps,
    dropped,
    used: { evidence: [...evLevel.keys()].sort(), attestations: items.filter((i) => i.att).map((i) => i.att.id).sort() },
    policy
  };
}
function graphFromEdges(ids, edges) {
  const req = /* @__PURE__ */ new Map();
  for (let i = 0; i < edges.length; i += 2) {
    const to = ids[edges[i + 1]], from = ids[edges[i]];
    const l = req.get(to) ?? [];
    l.push(from);
    req.set(to, l);
  }
  for (const l of req.values()) l.sort();
  return { requires: (id) => req.get(id) ?? [] };
}
var round32 = (x) => Math.round(x * 1e3) / 1e3;
function infer(graph, skill, level, confidence, policy, directClaims = []) {
  if (!(Number.isInteger(policy.maxInferenceDepth) && policy.maxInferenceDepth >= 0)) throw new RangeError("maxInferenceDepth must be an integer of at least 0");
  if (!(Number.isFinite(policy.inferenceDecay) && policy.inferenceDecay >= 0 && policy.inferenceDecay <= 1)) throw new RangeError("inferenceDecay must be a number from 0 to 1");
  const direct = new Set(directClaims);
  direct.add(skill);
  const out = [];
  const seen = /* @__PURE__ */ new Set([skill]);
  let layer = [{ id: skill, path: [skill] }];
  for (let d = 1; d <= policy.maxInferenceDepth && layer.length; d++) {
    const next = [];
    for (const n of layer) for (const p of [...graph.requires(n.id)].sort()) {
      if (seen.has(p)) continue;
      seen.add(p);
      const path = [...n.path, p];
      next.push({ id: p, path });
      const lv = Math.max(0, level - d);
      if (!direct.has(p) && lv > 0) out.push({ skill: p, level: lv, confidence: round32(confidence * Math.pow(policy.inferenceDecay, d)), distance: d, path, inferred: true });
    }
    layer = next.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  }
  return out.sort((a, b) => a.distance - b.distance || (a.skill < b.skill ? -1 : a.skill > b.skill ? 1 : 0));
}
function explainInference(skill, inferred, policy) {
  return { rule: "R8", summary: `${inferred.length} prerequisite skill(s) up to ${policy.maxInferenceDepth} step(s) back are INFERRED from ${skill}: level drops by 1 per step, confidence is multiplied by ${policy.inferenceDecay} per step. They are suggestions for the holder, never claims.`, inputs: inferred.map((i) => i.skill), effect: "flagged inferred; private until the holder publishes" };
}
var SAMPLE_SKILL = "B09";
var SAMPLE_NAMES = { "did:sanad:ember": "Ember (examiner)", "did:sanad:ash": "Ash (examiner)", "did:sanad:linden": "Linden (reviewer)", "did:sanad:fern": "Fern (fellow learner)" };
function sampleCredential() {
  return sealCredential({
    skill: SAMPLE_SKILL,
    claimedLevel: 4,
    subject: "urn:uuid:7c1f0b2e-sample-learner",
    evidence: [
      { id: "E1", kind: "auto", date: "2026-09-14", summary: "40 seeded epsilon-delta exercises, replayed from their seeds", body: { autoLevel: 3, exercises: 40, seeds: ["K7Q", "M2M", "QF8", "P6Q"], lecture: "limits" } },
      { id: "E2", kind: "sitting", date: "2026-10-20", summary: "Live sitting S-2026-014: 90 minutes, two examiners, whiteboard stroke log", body: { sitting: "S-2026-014", minutes: 90, strokeLogHead: "e3b0c442", paper: "B09-proofs" } },
      { id: "E3", kind: "artifact", date: "2026-10-02", summary: "Proof portfolio: three written proofs (hash of the PDF)", body: { file: "portfolio.pdf", sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", proofs: 3 } },
      { id: "E4", kind: "peer", date: "2026-09-30", summary: "Peer review by a fellow learner", body: { reviewer: "learner-7", rubric: "epsilon-delta-v1" } }
    ],
    attestations: [
      { id: "att-01", attestor: "did:sanad:ember", evidence: "E2", level: 4, role: "examiner", date: "2026-10-21" },
      { id: "att-02", attestor: "did:sanad:ash", evidence: "E2", level: 4, role: "examiner", date: "2026-10-21" },
      { id: "att-03", attestor: "did:sanad:linden", evidence: "E3", level: 4, role: "reviewer", date: "2026-10-05" },
      { id: "att-04", attestor: "did:sanad:fern", evidence: "E4", level: 3, role: "peer", date: "2026-10-01" }
    ],
    attestors: { "did:sanad:ember": { sittings: 14, agreement: 0.91 }, "did:sanad:ash": { sittings: 9, agreement: 0.88 }, "did:sanad:linden": { sittings: 6, agreement: 0.8 }, "did:sanad:fern": { sittings: 1, agreement: 0.7 } }
  });
}
var SAMPLE_TAMPER = [{ attestation: "att-02", set: { level: 5 } }];

// engine/src/errors.mjs
var EngineError = class extends Error {
  constructor(code, message, status = 400) {
    super(message || code);
    this.name = "EngineError";
    this.code = code;
    this.status = status;
  }
};
var fail = (code, message, status) => {
  throw new EngineError(code, message, status);
};

// engine/src/keys.mjs
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
var enc = new TextEncoder();
var dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function b64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
function fromB64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error("not base64url");
  const out = new Uint8Array(Buffer.from(s, "base64url"));
  if (b64u(out) !== s) throw new Error("not canonical base64url");
  return out;
}
var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var ALPHA_INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));
function base58btcEncode(bytes) {
  const b = Uint8Array.from(bytes);
  let zeros = 0;
  while (zeros < b.length && b[zeros] === 0) zeros++;
  let n = 0n;
  for (const x of b) n = n << 8n | BigInt(x);
  let s = "";
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  return "1".repeat(zeros) + s;
}
function base58btcDecode(str) {
  if (typeof str !== "string") throw new Error("not a string");
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  let n = 0n;
  for (const c of str) {
    const v = ALPHA_INDEX.get(c);
    if (v === void 0) throw new Error("bad base58 character");
    n = n * 58n + BigInt(v);
  }
  const hex = n === 0n ? "" : n.toString(16);
  const body = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  const out = new Uint8Array(zeros + body.length);
  out.set(body, zeros);
  return out;
}
var PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
var SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function publicKeyOf(privateKey) {
  const der = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  return new Uint8Array(der.subarray(SPKI_PREFIX.length));
}
function shape(privateKey) {
  return { publicKey: publicKeyOf(privateKey), privateKey };
}
function generateKeyPair() {
  return shape(generateKeyPairSync("ed25519").privateKey);
}
function keyPairFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error("seed must be 32 bytes");
  return shape(createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" }));
}
function exportPrivateKey(privateKey) {
  return b64u(privateKey.export({ type: "pkcs8", format: "der" }));
}
function importPrivateKey(str) {
  return createPrivateKey({ key: Buffer.from(fromB64u(str)), format: "der", type: "pkcs8" });
}
var P25519 = 2n ** 255n - 19n;
var D25519 = ((P25519 - 121665n * modPow(121666n, P25519 - 2n, P25519) % P25519) % P25519 + P25519) % P25519;
function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = r * b % m;
    b = b * b % m;
    e >>= 1n;
  }
  return r;
}
var inv = (a) => modPow((a % P25519 + P25519) % P25519, P25519 - 2n, P25519);
var SMALL_CACHE = /* @__PURE__ */ new Map();
function isSmallOrderKey(raw32) {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) return true;
  const k = Buffer.from(raw32).toString("hex");
  const hit = SMALL_CACHE.get(k);
  if (hit !== void 0) return hit;
  const v = computeSmallOrder(raw32);
  if (SMALL_CACHE.size >= 1024) SMALL_CACHE.delete(SMALL_CACHE.keys().next().value);
  SMALL_CACHE.set(k, v);
  return v;
}
function computeSmallOrder(raw32) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = y << 8n | BigInt(raw32[i]);
  y &= (1n << 255n) - 1n;
  y %= P25519;
  const y2 = y * y % P25519;
  const u = (y2 - 1n + P25519) % P25519, v = (D25519 * y2 + 1n) % P25519;
  const t = u * inv(v) % P25519;
  let x = modPow(t, (P25519 + 3n) / 8n, P25519);
  if (x * x % P25519 !== t) x = x * modPow(2n, (P25519 - 1n) / 4n, P25519) % P25519;
  if (x * x % P25519 !== t) return true;
  const add = (a, b) => {
    const k = D25519 * a[0] % P25519 * a[1] % P25519 * b[0] % P25519 * b[1] % P25519;
    return [(a[0] * b[1] + b[0] * a[1]) % P25519 * inv(1n + k) % P25519, (a[1] * b[1] + a[0] * b[0]) % P25519 * inv(1n - k) % P25519];
  };
  let q = [x, y];
  for (let i = 0; i < 3; i++) q = add(q, q);
  return q[0] === 0n && q[1] === 1n;
}
function publicKeyObject(raw32) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: "der", type: "spki" });
}
var DID_KEY = "did:key:";
function didKeyFromPublicKey(raw32) {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) throw new Error("public key must be 32 bytes");
  return DID_KEY + "z" + base58btcEncode(Uint8Array.from([237, 1, ...raw32]));
}
function publicKeyFromDidKey(did) {
  if (typeof did !== "string" || !did.startsWith(DID_KEY + "z")) throw new Error("not a did:key with a base58btc key");
  if (did.length > 80) throw new Error("did:key is too long");
  const bytes = base58btcDecode(did.slice(DID_KEY.length + 1));
  if (bytes.length !== 34 || bytes[0] !== 237 || bytes[1] !== 1) throw new Error("not an Ed25519 did:key");
  const key = bytes.slice(2);
  if (isSmallOrderKey(key)) throw new Error("key is not usable (small order or not on the curve)");
  return key;
}
function kidForDidKey(did) {
  return did + "#" + did.slice(DID_KEY.length);
}
function jwsHeader(typ, kid) {
  return canonical({ alg: "EdDSA", kid, typ });
}
var signingInput = (headerB64, payload) => headerB64 + "." + b64u(enc.encode(canonical(payload)));
function signJws({ typ, kid, payload, privateKey }) {
  const headerB64 = b64u(enc.encode(jwsHeader(typ, kid)));
  const sig = edSign(null, Buffer.from(signingInput(headerB64, payload), "utf8"), privateKey);
  return headerB64 + ".." + b64u(sig);
}
function parseJws(jws) {
  if (typeof jws !== "string") throw new Error("JWS must be a string");
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("JWS must have three parts");
  if (parts[1] !== "") throw new Error("JWS payload must be detached");
  const headerBytes = fromB64u(parts[0]);
  const header = JSON.parse(dec.decode(headerBytes));
  if (header === null || typeof header !== "object" || Array.isArray(header)) throw new Error("header must be an object");
  const names = Object.keys(header).sort();
  if (names.length !== 3 || names[0] !== "alg" || names[1] !== "kid" || names[2] !== "typ") throw new Error("header members must be exactly alg, kid, typ");
  if (header.alg !== "EdDSA") throw new Error("alg must be EdDSA");
  if (typeof header.kid !== "string" || typeof header.typ !== "string") throw new Error("kid and typ must be strings");
  if (dec.decode(headerBytes) !== canonical(header)) throw new Error("header is not in canonical form");
  const signature = fromB64u(parts[2]);
  if (signature.length !== 64) throw new Error("signature must be 64 bytes");
  return { header, headerB64: parts[0], signature };
}
function verifyJws({ jws, payload, typ, publicKey }) {
  try {
    const { header, headerB64, signature } = parseJws(jws);
    if (header.typ !== typ) return false;
    if (isSmallOrderKey(publicKey)) return false;
    return edVerify(null, Buffer.from(signingInput(headerB64, payload), "utf8"), publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}
function makeSigner(privateKey, did) {
  const publicKey = publicKeyOf(privateKey);
  const id = did ?? didKeyFromPublicKey(publicKey);
  const kid = did === void 0 ? kidForDidKey(id) : id + "#k1";
  return { did: id, kid, publicKey, sign: (typ, payload) => signJws({ typ, kid, payload, privateKey }) };
}
function isIsoDate(s) {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = /* @__PURE__ */ new Date(s + "T00:00:00Z");
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s && Number(s.slice(0, 4)) >= 100;
}
var KEY_ID_RE = /^#[A-Za-z0-9._-]{1,64}$/;
var isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var exactly = (o, names) => {
  const k = Object.keys(o).sort();
  return k.length === names.length && names.every((n, i) => k[i] === n);
};
var clone = (v) => JSON.parse(JSON.stringify(v));
function rawFromMultibase(s) {
  if (typeof s !== "string" || !s.startsWith("z") || s.length > 80) throw new Error("multibase must start with z");
  const raw = base58btcDecode(s.slice(1));
  if (raw.length !== 32) throw new Error("key must be 32 bytes");
  if (isSmallOrderKey(raw)) throw new Error("key is not usable (small order or not on the curve)");
  return raw;
}
function checkVersion(v, { expectRevokedEmpty }) {
  if (!isObj(v) || !exactly(v, ["keys", "revoked", "validFrom", "version"])) throw new Error("a version has exactly version, validFrom, keys, revoked");
  if (!Number.isInteger(v.version) || v.version < 1) throw new Error("version must be a positive integer");
  if (!isIsoDate(v.validFrom)) throw new Error("validFrom must be YYYY-MM-DD");
  if (!Array.isArray(v.keys) || v.keys.length === 0 || v.keys.length > DID_LIMITS.keys) throw new Error("keys must be a non-empty array of at most " + DID_LIMITS.keys);
  const ids = /* @__PURE__ */ new Set();
  for (const k of v.keys) {
    if (!isObj(k) || !exactly(k, ["id", "publicKeyMultibase"])) throw new Error("a key has exactly id and publicKeyMultibase");
    if (typeof k.id !== "string" || !KEY_ID_RE.test(k.id)) throw new Error("bad key id");
    if (ids.has(k.id)) throw new Error("duplicate key id");
    ids.add(k.id);
    rawFromMultibase(k.publicKeyMultibase);
  }
  if (!Array.isArray(v.revoked) || v.revoked.length > DID_LIMITS.revoked) throw new Error("revoked must be an array of at most " + DID_LIMITS.revoked);
  if (expectRevokedEmpty && v.revoked.length) throw new Error("version 1 has no revocations");
  for (const r of v.revoked) {
    if (!isObj(r) || !exactly(r, ["from", "id"])) throw new Error("a revocation has exactly id and from");
    if (typeof r.id !== "string" || !KEY_ID_RE.test(r.id) || !isIsoDate(r.from)) throw new Error("bad revocation");
  }
}
var DID_UPDATE_TYP = "sanad-did-update+jws";
var DID_LIMITS = { versions: 16, keys: 8, revoked: 16 };
function createResolver({ store } = {}) {
  const mem = /* @__PURE__ */ new Map();
  const load = (did, copy = true) => {
    const v = store ? store.get("dids", did) : mem.get(did);
    return v ? copy ? clone(v) : v : null;
  };
  const save = (did, doc) => {
    if (store) store.put("dids", did, doc);
    else mem.set(did, clone(doc));
  };
  const resolver = {
    get(did) {
      return load(did);
    },
    register(doc) {
      const bad2 = (m) => new EngineError("bad_did_document", m, 400);
      if (!isObj(doc) || !exactly(doc, ["id", "versions"])) throw bad2("a DID document history has exactly id and versions");
      if (typeof doc.id !== "string" || !/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(doc.id) || doc.id.length > 200) throw bad2("bad DID");
      if (doc.id.startsWith(DID_KEY)) throw new EngineError("bad_did_document", "did:key needs no registration", 400);
      if (!Array.isArray(doc.versions) || doc.versions.length !== 1) throw bad2("registration carries exactly version 1");
      const v = doc.versions[0];
      try {
        checkVersion(v, { expectRevokedEmpty: true });
      } catch (e) {
        throw bad2(e.message);
      }
      if (v.version !== 1) throw bad2("the first version must be 1");
      if (load(doc.id)) throw new EngineError("did_exists", "DID already registered: " + doc.id, 409);
      save(doc.id, { id: doc.id, versions: [clone(v)] });
      return load(doc.id);
    },
    update(did, version, jws) {
      const hist = load(did);
      if (!hist) throw new EngineError("did_unknown", "DID not registered: " + did, 404);
      const bad2 = (m) => new EngineError("bad_did_update", m, 400);
      try {
        checkVersion(version, { expectRevokedEmpty: false });
      } catch (e) {
        throw bad2(e.message);
      }
      if (hist.versions.length >= DID_LIMITS.versions) throw bad2("a history holds at most " + DID_LIMITS.versions + " versions");
      const last = hist.versions[hist.versions.length - 1];
      if (version.version !== last.version + 1) throw bad2("version must be " + (last.version + 1));
      if (version.validFrom < last.validFrom) throw bad2("validFrom must not be before the previous version");
      const res = resolver.verifyStatement({ jws, payload: { did, ...version }, typ: DID_UPDATE_TYP, signer: did, date: version.validFrom });
      if (!res.ok) throw bad2("update signature refused: " + res.reason);
      hist.versions.push(clone(version));
      save(did, hist);
      return load(did);
    },
    keysAt(did, date) {
      if (typeof did === "string" && did.startsWith(DID_KEY)) {
        try {
          return [{ kid: kidForDidKey(did), publicKey: publicKeyFromDidKey(did) }];
        } catch {
          return [];
        }
      }
      if (!isIsoDate(date)) return [];
      const hist = load(did, false);
      if (!hist) return [];
      let inForce = null;
      for (const v of hist.versions) if (v.validFrom <= date) inForce = v;
      if (!inForce) return [];
      const revoked = /* @__PURE__ */ new Set();
      for (const v of hist.versions) for (const r of v.revoked) if (r.from <= date) revoked.add(r.id);
      return inForce.keys.filter((k) => !revoked.has(k.id)).map((k) => ({ kid: did + k.id, publicKey: rawFromMultibase(k.publicKeyMultibase) }));
    },
    /** The one key named by `kid` that is valid on `date`, decoded alone (no work for the other keys of the version). */
    keyAt(did, kid, date) {
      if (typeof did === "string" && did.startsWith(DID_KEY)) {
        try {
          return kid === kidForDidKey(did) ? { kid, publicKey: publicKeyFromDidKey(did) } : null;
        } catch {
          return null;
        }
      }
      if (!isIsoDate(date) || typeof kid !== "string" || !kid.startsWith(did + "#")) return null;
      const hist = load(did, false);
      if (!hist) return null;
      let inForce = null;
      for (const v of hist.versions) if (v.validFrom <= date) inForce = v;
      if (!inForce) return null;
      const frag = kid.slice(did.length);
      const entry = inForce.keys.find((k) => k.id === frag);
      if (!entry) return null;
      for (const v of hist.versions) for (const r of v.revoked) if (r.id === frag && r.from <= date) return null;
      try {
        return { kid, publicKey: rawFromMultibase(entry.publicKeyMultibase) };
      } catch {
        return null;
      }
    },
    verifyStatement({ jws, payload, typ, signer, date }) {
      let parsed;
      try {
        parsed = parseJws(jws);
      } catch {
        return { ok: false, reason: "bad_jws" };
      }
      const { header } = parsed;
      if (typeof signer !== "string" || !header.kid.startsWith(signer + "#")) return { ok: false, reason: "kid_mismatch" };
      if (header.typ !== typ) return { ok: false, reason: "wrong_type" };
      let key;
      try {
        key = resolver.keyAt(signer, header.kid, date);
      } catch {
        key = null;
      }
      if (!key) return { ok: false, reason: "key_not_valid" };
      if (!verifyJws({ jws, payload, typ, publicKey: key.publicKey })) return { ok: false, reason: "bad_signature" };
      return { ok: true, kid: key.kid, publicKey: key.publicKey };
    }
  };
  return resolver;
}

// engine/src/commit.mjs
var NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/;
var HEX64 = /^[0-9a-f]{64}$/;
function newNonce() {
  return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).toString("base64url");
}
function commitFor({ attestor, evidence, level, nonce }) {
  return commitOf({ attestor, evidence, level, nonce });
}
var isStr = (v) => typeof v === "string" && v.length > 0;
var isObj2 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var hasExactly = (o, names) => {
  const k = Object.keys(o).sort();
  const n = [...names].sort();
  return k.length === n.length && k.every((x, i) => x === n[i]);
};
function commitStatement({ assessment, attestationId, attestor, evidence, role, commit, templateHash: templateHash2 }) {
  for (const [k, v] of Object.entries({ assessment, attestationId, attestor, evidence, role })) {
    if (!isStr(v)) throw new EngineError("bad_commit", k + " must be a non-empty string");
  }
  if (typeof commit !== "string" || !HEX64.test(commit)) throw new EngineError("bad_commit", "commit must be 64 lowercase hex characters");
  if (typeof templateHash2 !== "string" || !HEX64.test(templateHash2)) throw new EngineError("bad_commit", "templateHash must be 64 lowercase hex characters");
  return { type: "sanad-commit", assessment, attestationId, attestor, evidence, role, commit, templateHash: templateHash2 };
}
var ATTESTATION_MEMBERS = ["id", "attestor", "evidence", "level", "role", "conflictDeclared", "date", "commit", "nonce"];
function attestationStatement({ id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce }) {
  return { id, attestor, evidence, level, role, conflictDeclared, date, commit, nonce };
}
function checkCommit({ payload, invitation, assessment }) {
  if (!isObj2(payload) || !hasExactly(payload, ["type", "assessment", "attestationId", "attestor", "evidence", "role", "commit", "templateHash"])) {
    throw new EngineError("bad_commit", "a commit statement has exactly type, assessment, attestationId, attestor, evidence, role, commit, templateHash");
  }
  if (typeof payload.commit !== "string" || !HEX64.test(payload.commit)) throw new EngineError("bad_commit", "commit must be 64 lowercase hex characters");
  const expected = commitStatement({
    assessment: assessment.id,
    attestationId: invitation.attestationId,
    attestor: invitation.attestor,
    evidence: invitation.evidence,
    role: invitation.role,
    commit: payload.commit,
    templateHash: assessment.templateHash
  });
  if (canonical(payload) !== canonical(expected)) throw new EngineError("commit_mismatch_invitation", "the commit statement does not match the invitation and the assessment");
}
function checkReveal({ statement, invitation, storedCommit, evidenceDate, revealDay, allowedLevels }) {
  const s = statement;
  if (!isObj2(s) || !hasExactly(s, ATTESTATION_MEMBERS)) throw new EngineError("bad_statement", "an attestation statement has exactly " + ATTESTATION_MEMBERS.join(", "));
  for (const k of ["id", "attestor", "evidence", "role", "commit"]) if (typeof s[k] !== "string") throw new EngineError("bad_statement", k + " must be a string");
  if (typeof s.conflictDeclared !== "boolean") throw new EngineError("bad_statement", "conflictDeclared must be true or false");
  if (s.id !== invitation.attestationId || s.attestor !== invitation.attestor || s.evidence !== invitation.evidence || s.role !== invitation.role) {
    throw new EngineError("statement_mismatch", "id, attestor, evidence and role must equal the invitation");
  }
  const allowed = allowedLevels ?? [0, 1, 2, 3, 4, 5];
  if (!Number.isInteger(s.level) || s.level < 0 || s.level > 5 || !allowed.includes(s.level)) throw new EngineError("bad_level", "level must be an integer from 0 to 5 that the template allows");
  if (!isIsoDate(s.date)) throw new EngineError("bad_date", "date must be a valid YYYY-MM-DD");
  if (evidenceDate !== void 0 && s.date < evidenceDate) throw new EngineError("bad_date", "date is before the evidence date");
  if (revealDay !== void 0 && s.date > revealDay) throw new EngineError("bad_date", "date is after the reveal day");
  if (typeof s.nonce !== "string" || !NONCE_RE.test(s.nonce)) throw new EngineError("bad_nonce", "nonce must be 22 to 128 base64url characters");
  if (s.commit !== storedCommit || commitFor(s) !== storedCommit) throw new EngineError("commit_mismatch", "the reveal does not match the stored commit");
}

// engine/src/template.mjs
var ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;
var KINDS2 = ["auto", "sitting", "artifact", "peer"];
var isObj3 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var isStr2 = (v) => typeof v === "string" && v.length > 0;
var isLevel = (v) => Number.isInteger(v) && v >= 0 && v <= 5;
var isNum2 = (v) => typeof v === "number" && Number.isFinite(v);
function jsonSafe(v, depth = 0) {
  if (depth > 12) return false;
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (Array.isArray(v)) return v.every((x) => jsonSafe(x, depth + 1));
  if (isObj3(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v))) return Object.keys(v).every((k) => jsonSafe(v[k], depth + 1));
  return false;
}
var MAX_HOURS = 87600;
function closed(o, required, optional, where, errors) {
  for (const k of Object.keys(o)) if (!required.includes(k) && !optional.includes(k)) errors.push(where + ': unknown member "' + k + '"');
  for (const k of required) if (!(k in o)) errors.push(where + ': missing member "' + k + '"');
}
var POLICY_FIELDS = ["minAttestors", "requireLive", "halfLifeMonths", "minAttestorSittings", "minAgreement", "maxInferenceDepth", "inferenceDecay"];
function validateTemplate(t) {
  const errors = [];
  if (!isObj3(t)) return { ok: false, errors: ["template must be an object"] };
  closed(t, ["id", "version", "title", "skill", "levels", "evidence", "attestors", "liveSitting", "deadlines", "policy"], ["rubric", "description", "levelMap"], "template", errors);
  if ("id" in t && !(typeof t.id === "string" && ID_RE.test(t.id))) errors.push("id: must match " + ID_RE);
  if ("version" in t && !(Number.isInteger(t.version) && t.version >= 1)) errors.push("version: must be an integer of at least 1");
  if ("title" in t && !isStr2(t.title)) errors.push("title: must be a non-empty string");
  if ("description" in t && typeof t.description !== "string") errors.push("description: must be a string");
  if ("skill" in t) {
    const s = t.skill;
    if (!isObj3(s)) errors.push("skill: must be an object");
    else {
      closed(s, ["id", "title"], ["graphHash", "xwalk"], "skill", errors);
      if ("id" in s && !(typeof s.id === "string" && ID_RE.test(s.id))) errors.push("skill.id: must match " + ID_RE);
      if ("title" in s && !isStr2(s.title)) errors.push("skill.title: must be a non-empty string");
      if ("graphHash" in s && !isStr2(s.graphHash)) errors.push("skill.graphHash: must be a non-empty string");
      if ("xwalk" in s && !(isObj3(s.xwalk) && jsonSafe(s.xwalk))) errors.push("skill.xwalk: must be an object of plain JSON values (finite numbers, nesting up to 12)");
    }
  }
  if ("levels" in t) {
    if (!Array.isArray(t.levels) || t.levels.length === 0) errors.push("levels: must be a non-empty array");
    else {
      const seen = /* @__PURE__ */ new Set();
      t.levels.forEach((l, i) => {
        const w = "levels[" + i + "]";
        if (!isObj3(l)) {
          errors.push(w + ": must be an object");
          return;
        }
        closed(l, ["level", "label"], [], w, errors);
        if ("level" in l) {
          if (!isLevel(l.level)) errors.push(w + ".level: must be an integer from 0 to 5");
          else if (seen.has(l.level)) errors.push(w + ".level: duplicate level " + l.level);
          else seen.add(l.level);
        }
        if ("label" in l && !isStr2(l.label)) errors.push(w + ".label: must be a non-empty string");
      });
    }
  }
  if ("rubric" in t) {
    if (!Array.isArray(t.rubric)) errors.push("rubric: must be an array");
    else {
      const seen = /* @__PURE__ */ new Set();
      t.rubric.forEach((r, i) => {
        const w = "rubric[" + i + "]";
        if (!isObj3(r)) {
          errors.push(w + ": must be an object");
          return;
        }
        closed(r, ["id", "criterion", "descriptors"], [], w, errors);
        if ("id" in r) {
          if (!(typeof r.id === "string" && ID_RE.test(r.id))) errors.push(w + ".id: must match " + ID_RE);
          else if (seen.has(r.id)) errors.push(w + ".id: duplicate id");
          else seen.add(r.id);
        }
        if ("criterion" in r && !isStr2(r.criterion)) errors.push(w + ".criterion: must be a non-empty string");
        if ("descriptors" in r) {
          if (!isObj3(r.descriptors)) errors.push(w + ".descriptors: must be an object");
          else for (const [k, v] of Object.entries(r.descriptors)) {
            if (!/^[0-5]$/.test(k)) errors.push(w + '.descriptors: key "' + k + '" is not a level from 0 to 5');
            if (typeof v !== "string") errors.push(w + ".descriptors." + k + ": must be a string");
          }
        }
      });
    }
  }
  let hasSitting = false;
  if ("evidence" in t) {
    if (!Array.isArray(t.evidence) || t.evidence.length === 0) errors.push("evidence: must be a non-empty array");
    else {
      const seen = /* @__PURE__ */ new Set();
      t.evidence.forEach((e, i) => {
        const w = "evidence[" + i + "]";
        if (!isObj3(e)) {
          errors.push(w + ": must be an object");
          return;
        }
        closed(e, ["key", "kind", "summary"], ["live", "minutes"], w, errors);
        if ("key" in e) {
          if (!(typeof e.key === "string" && ID_RE.test(e.key))) errors.push(w + ".key: must match " + ID_RE);
          else if (seen.has(e.key)) errors.push(w + ".key: duplicate key");
          else seen.add(e.key);
        }
        if ("kind" in e) {
          if (!KINDS2.includes(e.kind)) errors.push(w + ".kind: must be one of " + KINDS2.join(", "));
          else if (e.kind === "sitting") hasSitting = true;
        }
        if ("summary" in e && typeof e.summary !== "string") errors.push(w + ".summary: must be a string");
        if ("live" in e && typeof e.live !== "boolean") errors.push(w + ".live: must be true or false");
        if ("minutes" in e && !(isNum2(e.minutes) && e.minutes > 0)) errors.push(w + ".minutes: must be a positive number");
      });
    }
  }
  if ("attestors" in t) {
    const a = t.attestors;
    if (!isObj3(a)) errors.push("attestors: must be an object");
    else {
      closed(a, ["min", "max", "roles"], [], "attestors", errors);
      const okMin = Number.isInteger(a.min) && a.min >= 1, okMax = Number.isInteger(a.max) && a.max >= 1;
      if ("min" in a && !okMin) errors.push("attestors.min: must be an integer of at least 1");
      if ("max" in a && !okMax) errors.push("attestors.max: must be an integer of at least 1");
      if (okMin && okMax && a.min > a.max) errors.push("attestors: min must not exceed max");
      if ("roles" in a) {
        if (!Array.isArray(a.roles) || a.roles.length === 0) errors.push("attestors.roles: must be a non-empty array");
        else {
          if (!a.roles.every(isStr2)) errors.push("attestors.roles: every role must be a non-empty string");
          if (new Set(a.roles).size !== a.roles.length) errors.push("attestors.roles: duplicate role");
        }
      }
    }
  }
  if ("liveSitting" in t) {
    if (typeof t.liveSitting !== "boolean") errors.push("liveSitting: must be true or false");
    else if (t.liveSitting && Array.isArray(t.evidence) && !hasSitting) errors.push("liveSitting: true needs at least one evidence item of kind sitting");
  }
  if ("deadlines" in t) {
    const d = t.deadlines;
    if (!isObj3(d)) errors.push("deadlines: must be an object");
    else {
      closed(d, ["commitHours", "revealHours"], [], "deadlines", errors);
      for (const k of ["commitHours", "revealHours"]) if (k in d && !(isNum2(d[k]) && d[k] > 0 && d[k] <= MAX_HOURS)) errors.push("deadlines." + k + ": must be a positive number of at most " + MAX_HOURS);
    }
  }
  if ("levelMap" in t) {
    if (!isObj3(t.levelMap)) errors.push("levelMap: must be an object");
    else for (const [k, v] of Object.entries(t.levelMap)) {
      if (!/^[A-Za-z0-9]{1,16}$/.test(k)) errors.push('levelMap: key "' + k + '" must be 1 to 16 letters or digits (it is written into the nonce)');
      if (k in Object.prototype) errors.push('levelMap: key "' + k + '" is reserved');
      if (!isLevel(v)) errors.push("levelMap." + k + ": must be an integer from 0 to 5");
    }
  }
  if ("policy" in t) {
    const p = t.policy;
    if (!isObj3(p)) errors.push("policy: must be an object");
    else {
      closed(p, ["id", ...POLICY_FIELDS], [], "policy", errors);
      if ("id" in p && !(typeof p.id === "string" && ID_RE.test(p.id))) errors.push("policy.id: must match " + ID_RE);
      const num = (k, ok, what) => {
        if (k in p && !(isNum2(p[k]) && ok(p[k]))) errors.push("policy." + k + ": must be " + what);
      };
      num("minAttestors", (v) => Number.isInteger(v) && v >= 1, "an integer of at least 1");
      if ("requireLive" in p && typeof p.requireLive !== "boolean") errors.push("policy.requireLive: must be true or false");
      num("halfLifeMonths", (v) => v > 0, "a number above 0");
      num("minAttestorSittings", (v) => v >= 0, "a number of at least 0");
      num("minAgreement", (v) => v >= 0 && v <= 1, "a number from 0 to 1");
      num("maxInferenceDepth", (v) => Number.isInteger(v) && v >= 0, "an integer of at least 0");
      num("inferenceDecay", (v) => v >= 0 && v <= 1, "a number from 0 to 1");
    }
  }
  return { ok: errors.length === 0, errors };
}
function assertTemplate(t) {
  const r = validateTemplate(t);
  if (!r.ok) throw new EngineError("bad_template", r.errors.join("; "), 400);
  return t;
}
function templateHash(t) {
  return hashOf(t);
}
function policyFromTemplate(t, asOf) {
  const p = t.policy;
  return {
    minAttestors: p.minAttestors,
    requireLive: p.requireLive,
    halfLifeMonths: p.halfLifeMonths,
    minAttestorSittings: p.minAttestorSittings,
    minAgreement: p.minAgreement,
    maxInferenceDepth: p.maxInferenceDepth,
    inferenceDecay: p.inferenceDecay,
    asOf
  };
}
var NATIVE_NONCE = /^nm-([A-Za-z0-9]{1,16})-[A-Za-z0-9_-]{16,}$/;
function levelFromNative(levelMap, native) {
  if (!levelMap || typeof levelMap !== "object" || !Object.hasOwn(levelMap, String(native))) throw new EngineError("native_unknown", "the levelMap has no native mark " + native, 400);
  return levelMap[String(native)];
}
function nonceWithNative(native, random) {
  if (!/^[A-Za-z0-9]{1,16}$/.test(String(native))) throw new EngineError("bad_nonce", "native mark must be 1 to 16 letters or digits");
  return "nm-" + native + "-" + random;
}
function nativeOfNonce(nonce) {
  const m = typeof nonce === "string" ? NATIVE_NONCE.exec(nonce) : null;
  return m ? m[1] : null;
}
function validatePolicy(p) {
  return policyProblems(p);
}

// engine/src/stats.mjs
var lowerMedian2 = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor((s.length - 1) / 2)];
};
function attestorStats(records) {
  const acc = /* @__PURE__ */ new Map();
  const get = (did) => {
    let a = acc.get(did);
    if (!a) acc.set(did, a = { sittings: 0, agree: 0, total: 0 });
    return a;
  };
  for (const rec of records) {
    const kinds = new Map(rec.evidence.map((e) => [e.id, e.kind]));
    const byItem = /* @__PURE__ */ new Map();
    for (const m of rec.marks) {
      if (!byItem.has(m.evidence)) byItem.set(m.evidence, []);
      byItem.get(m.evidence).push(m);
    }
    const sat = /* @__PURE__ */ new Set();
    for (const [item, marks] of byItem) {
      for (const m of marks) {
        const a = get(m.attestor);
        if (kinds.get(item) === "sitting") sat.add(m.attestor);
        const others = marks.filter((o) => o.attestor !== m.attestor).map((o) => o.level);
        if (others.length === 0) continue;
        a.total++;
        if (Math.abs(m.level - lowerMedian2(others)) <= 1) a.agree++;
      }
    }
    for (const did of sat) get(did).sittings++;
  }
  const out = {};
  for (const did of [...acc.keys()].sort()) {
    const a = acc.get(did);
    Object.defineProperty(out, did, { enumerable: true, configurable: true, writable: true, value: { sittings: a.sittings, agreement: a.total === 0 ? 0 : Math.round(a.agree / a.total * 1e3) / 1e3 } });
  }
  return out;
}

// engine/src/log.mjs
import { createHash } from "node:crypto";
var HEX642 = /^[0-9a-f]{64}$/;
var KINDS3 = ["commit", "attestation", "missing-reveal", "bundle"];
var sha = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
};
var hexBytes = (h) => Buffer.from(h, "hex");
var ZERO = Buffer.from([0]);
var ONE = Buffer.from([1]);
function leafHash(bytes) {
  const b = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
  return sha(ZERO, b);
}
var nodeHash = (l, r) => sha(ONE, hexBytes(l), hexBytes(r));
var split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
function merkleRoot(leaves) {
  const n = leaves.length;
  if (n === 0) return sha();
  if (n === 1) return leaves[0];
  const k = split(n);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}
function checkTree(leaves, size) {
  if (!Array.isArray(leaves) || !Number.isInteger(size) || size < 0 || size > leaves.length) throw new EngineError("bad_range", "invalid tree size");
}
function inclusionProof(leaves, index, size) {
  checkTree(leaves, size);
  if (!Number.isInteger(index) || index < 0 || index >= size) throw new EngineError("bad_range", "index outside tree");
  const path = (m, d) => {
    if (d.length === 1) return [];
    const k = split(d.length);
    return m < k ? [...path(m, d.slice(0, k)), merkleRoot(d.slice(k))] : [...path(m - k, d.slice(k)), merkleRoot(d.slice(0, k))];
  };
  return path(index, leaves.slice(0, size));
}
function consistencyProof(leaves, m, n) {
  checkTree(leaves, n);
  if (!Number.isInteger(m) || m < 1 || m > n) throw new EngineError("bad_range", "consistency needs 1 <= m <= n");
  const sub = (mm, d, b) => {
    if (mm === d.length) return b ? [] : [merkleRoot(d)];
    const k = split(d.length);
    return mm <= k ? [...sub(mm, d.slice(0, k), b), merkleRoot(d.slice(k))] : [...sub(mm - k, d.slice(k), false), merkleRoot(d.slice(0, k))];
  };
  return sub(m, leaves.slice(0, n), true);
}
var TS = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-](\d\d):(\d\d))$/;
function isIsoTime(ts) {
  const m = typeof ts === "string" ? TS.exec(ts) : null;
  if (!m) return false;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return false;
  if (m[9] !== void 0 && (Number(m[9]) > 23 || Number(m[10]) > 59)) return false;
  if (d > new Date(Date.UTC(2e3 + y % 400, mo, 0)).getUTCDate()) return false;
  return !Number.isNaN(Date.parse(ts));
}
var okHex = (h) => typeof h === "string" && HEX642.test(h);
var okProof = (p) => Array.isArray(p) && p.every(okHex);
var isSize = (x) => Number.isSafeInteger(x) && x >= 0;
var half = (x) => Math.floor(x / 2);
function verifyInclusion(arg) {
  try {
    const { leafHash: lh, index, size, proof, root } = arg;
    if (!okHex(lh) || !okHex(root) || !okProof(proof) || !isSize(index) || !isSize(size) || index >= size) return false;
    let fn = index, sn = size - 1, r = lh;
    for (const p of proof) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = nodeHash(p, r);
        if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      } else r = nodeHash(r, p);
      fn = half(fn);
      sn = half(sn);
    }
    return sn === 0 && r === root;
  } catch {
    return false;
  }
}
function verifyConsistency(arg) {
  try {
    const { m, n, proof, rootM, rootN } = arg;
    if (!isSize(m) || !isSize(n) || !okHex(rootM) || !okHex(rootN) || !okProof(proof) || m < 1 || m > n) return false;
    if (m === n) return proof.length === 0 && rootM === rootN;
    const path = (m & m - 1) === 0 ? [rootM, ...proof] : [...proof];
    if (path.length === 0) return false;
    let fn = m - 1, sn = n - 1;
    while (fn % 2 === 1) {
      fn = half(fn);
      sn = half(sn);
    }
    let fr = path[0], sr = path[0];
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        fr = nodeHash(c, fr);
        sr = nodeHash(c, sr);
        if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      } else sr = nodeHash(sr, c);
      fn = half(fn);
      sn = half(sn);
    }
    return sn === 0 && fr === rootM && sr === rootN;
  } catch {
    return false;
  }
}
function leafBytes({ kind, ref, ts } = {}) {
  if (!KINDS3.includes(kind)) throw new EngineError("bad_leaf", "unknown leaf kind");
  if (typeof ref !== "string" || !HEX642.test(ref)) throw new EngineError("bad_leaf", "ref must be 64 lowercase hex characters");
  if (!isIsoTime(ts)) throw new EngineError("bad_leaf", "ts must be an ISO date-time");
  return canonical({ kind, ref, ts });
}
var entryHash = (e) => sha256Hex(canonical({ index: e.index, leaf: e.leaf, leafHash: e.leafHash, prev: e.prev }));
var ENTRY_KEYS = ["hash", "index", "leaf", "leafHash", "prev"];
function firstBadEntry(all, hashes) {
  let prev = "GENESIS";
  for (let i = 0; i < all.length; i++) {
    const e = all[i];
    if (!e || typeof e !== "object" || Array.isArray(e) || Object.keys(e).sort().join() !== ENTRY_KEYS.join()) return i;
    if (e.index !== i || typeof e.leaf !== "string" || e.prev !== prev || !okHex(e.leafHash) || !okHex(e.hash)) return i;
    if (e.leafHash !== leafHash(e.leaf) || e.leafHash !== hashes[i] || e.hash !== entryHash(e)) return i;
    try {
      if (leafBytes(JSON.parse(e.leaf)) !== e.leaf) return i;
    } catch {
      return i;
    }
    prev = e.hash;
  }
  return -1;
}
function createLog({ store, stream = "log", logId, signer = null, clock = { now: () => Date.now() } } = {}) {
  if (!store) throw new EngineError("bad_config", "a store is required");
  if (typeof logId !== "string" || !logId) throw new EngineError("bad_config", "logId is required");
  const stored = store.read(stream);
  const hashes = stored.map((e) => e?.leafHash);
  const byLeaf = /* @__PURE__ */ new Map();
  stored.forEach((e, i) => {
    try {
      const l = JSON.parse(e.leaf);
      const k = l.kind + ":" + l.ref;
      if (!byLeaf.has(k)) byLeaf.set(k, i);
    } catch {
    }
  });
  let lastHash = stored.length ? stored[stored.length - 1]?.hash : "GENESIS";
  const size = () => hashes.length;
  const sz = (s) => {
    const v = s === void 0 ? size() : s;
    if (!Number.isInteger(v) || v < 0 || v > size()) throw new EngineError("bad_range", "size outside log");
    return v;
  };
  const rootOf = (s) => merkleRoot(hashes.slice(0, sz(s)));
  const loadedOk = firstBadEntry(stored, hashes) < 0;
  const chainOk = () => loadedOk;
  return {
    logId,
    append({ kind, ref } = {}) {
      if (!chainOk(stored)) throw new EngineError("log_corrupt", "the stored log does not verify; refusing to append", 500);
      const leaf = leafBytes({ kind, ref, ts: new Date(clock.now()).toISOString() });
      const lh = leafHash(leaf);
      const entry = { index: hashes.length, leaf, leafHash: lh, prev: lastHash };
      entry.hash = entryHash(entry);
      const at = store.append(stream, entry);
      if (at !== entry.index) throw new EngineError("log_conflict", "stream index does not match the log", 500);
      hashes.push(lh);
      lastHash = entry.hash;
      const key = kind + ":" + ref;
      if (!byLeaf.has(key)) byLeaf.set(key, entry.index);
      return { index: entry.index, leaf, leafHash: lh };
    },
    /** Appends the leaf unless a leaf of the same kind and ref is already in the log (idempotent retry); returns { index, leaf, leafHash, existed }. */
    appendOnce({ kind, ref } = {}) {
      const at = byLeaf.get(kind + ":" + ref);
      if (at !== void 0) {
        const e = store.read(stream, at, at + 1)[0];
        return { index: at, leaf: e.leaf, leafHash: e.leafHash, existed: true };
      }
      return { ...this.append({ kind, ref }), existed: false };
    },
    size,
    root: (s) => rootOf(s),
    entries: (from = 0, to = size()) => store.read(stream, from, to),
    inclusion(index, s) {
      const n = sz(s);
      const proof = inclusionProof(hashes, index, n);
      return { index, size: n, leafHash: hashes[index], proof, root: rootOf(n) };
    },
    consistency(m, n) {
      const nn = sz(n);
      return { m, n: nn, proof: consistencyProof(hashes, m, nn), rootM: rootOf(m), rootN: rootOf(nn) };
    },
    checkpoint() {
      const payload = { logId, size: size(), rootHash: rootOf(), timestamp: new Date(clock.now()).toISOString() };
      return { payload, jws: signer ? signer.sign("sanad-checkpoint+jws", payload) : null };
    },
    verifyChain() {
      const all = store.read(stream);
      if (all.length !== hashes.length) return { ok: false, at: Math.min(all.length, hashes.length) };
      const bad2 = firstBadEntry(all, hashes);
      return bad2 < 0 ? { ok: true } : { ok: false, at: bad2 };
    },
    findByRef(ref) {
      return store.read(stream).filter((e) => {
        try {
          return JSON.parse(e.leaf).ref === ref;
        } catch {
          return false;
        }
      });
    }
  };
}
function verifyCheckpoint(checkpoint, verify) {
  try {
    const p = checkpoint?.payload;
    if (!p || typeof checkpoint.jws !== "string" || typeof verify !== "function") return false;
    if (typeof p !== "object" || Array.isArray(p) || Object.keys(p).sort().join() !== "logId,rootHash,size,timestamp") return false;
    if (typeof p.logId !== "string" || !isSize(p.size) || !okHex(p.rootHash) || !isIsoTime(p.timestamp)) return false;
    return verify(checkpoint.jws, p, "sanad-checkpoint+jws") === true;
  } catch {
    return false;
  }
}

// engine/src/store/memory.mjs
var NAME = /^[A-Za-z0-9._:-]{1,200}$/;
function checkName(name, what = "id") {
  if (typeof name !== "string" || !NAME.test(name) || name === "." || name === "..") {
    throw new EngineError("bad_id", `invalid ${what}: must match ${NAME}`);
  }
  return name;
}
function toJson(value) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch (e) {
    throw new EngineError("bad_value", "value is not JSON-serialisable");
  }
  if (typeof text !== "string") throw new EngineError("bad_value", "value is not JSON-serialisable");
  return text;
}
var fromJson = (text) => JSON.parse(text);
function checkRange(from, to, size) {
  const f = from, t = to === void 0 ? size : to;
  if (!Number.isInteger(f) || !Number.isInteger(t) || f < 0 || t > size || f > t) {
    throw new EngineError("bad_range", `invalid range [${from}, ${to}) for size ${size}`);
  }
  return [f, t];
}
function createMemoryStore() {
  const cols = /* @__PURE__ */ new Map();
  const streams = /* @__PURE__ */ new Map();
  let closed2 = false;
  const open = () => {
    if (closed2) throw new EngineError("store_closed", "store is closed", 500);
  };
  return {
    get(collection, id) {
      open();
      checkName(collection, "collection");
      checkName(id);
      const t = cols.get(collection)?.get(id);
      return t === void 0 ? null : fromJson(t);
    },
    put(collection, id, value) {
      open();
      checkName(collection, "collection");
      checkName(id);
      const t = toJson(value);
      if (!cols.has(collection)) cols.set(collection, /* @__PURE__ */ new Map());
      cols.get(collection).set(id, t);
    },
    list(collection) {
      open();
      checkName(collection, "collection");
      const m = cols.get(collection);
      if (!m) return [];
      return [...m.keys()].sort().map((k) => fromJson(m.get(k)));
    },
    append(stream, value) {
      open();
      checkName(stream, "stream");
      const t = toJson(value);
      if (!streams.has(stream)) streams.set(stream, []);
      const a = streams.get(stream);
      a.push(t);
      return a.length - 1;
    },
    read(stream, from = 0, to) {
      open();
      checkName(stream, "stream");
      const a = streams.get(stream) || [];
      const [f, t] = checkRange(from, to, a.length);
      return a.slice(f, t).map(fromJson);
    },
    size(stream) {
      open();
      checkName(stream, "stream");
      return (streams.get(stream) || []).length;
    },
    close() {
      closed2 = true;
    }
  };
}

// engine/src/store/file.mjs
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  readdirSync,
  existsSync,
  openSync,
  closeSync,
  fsyncSync,
  writeSync,
  ftruncateSync,
  unlinkSync,
  lstatSync,
  fstatSync,
  constants
} from "node:fs";
import { join } from "node:path";
import { createHash as createHash2, randomBytes } from "node:crypto";
function encodeName(name) {
  const enc2 = name.replace(/[A-Z]/g, (c) => "+" + c.toLowerCase()).replace(/:/g, "=");
  return enc2.length <= 150 ? enc2 : "h" + createHash2("sha256").update(name, "utf8").digest("hex");
}
var DIR_MODE = 448;
var FILE_MODE = 384;
var NOFOLLOW = constants.O_NOFOLLOW || 0;
function writeAll(fd, bytes, pos) {
  let off = 0;
  while (off < bytes.length) {
    const n = writeSync(fd, bytes, off, bytes.length - off, pos === void 0 ? null : pos + off);
    if (!(n > 0)) throw new EngineError("store_io", "short write", 500);
    off += n;
  }
}
function syncDir(d) {
  try {
    const fd = openSync(d, constants.O_RDONLY);
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
  }
}
function plainDir(d) {
  const st = lstatSync(d);
  if (!st.isDirectory()) throw new EngineError("store_corrupt", "storage path is not a plain directory", 500);
}
function readPlain(path) {
  const fd = openSync(path, constants.O_RDONLY | NOFOLLOW);
  try {
    if (!fstatSync(fd).isFile()) throw new EngineError("store_corrupt", "storage path is not a regular file", 500);
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}
var record = (text) => {
  let r;
  try {
    r = fromJson(text);
  } catch {
    throw new EngineError("store_corrupt", "unreadable record file", 500);
  }
  if (!r || typeof r !== "object" || Array.isArray(r) || typeof r.id !== "string" || !("value" in r)) throw new EngineError("store_corrupt", "malformed record file", 500);
  return r;
};
function createFileStore(dir) {
  if (typeof dir !== "string" || !dir) throw new EngineError("bad_dir", "a directory is required");
  const colRoot = join(dir, "collections"), strRoot = join(dir, "streams");
  mkdirSync(colRoot, { recursive: true, mode: DIR_MODE });
  mkdirSync(strRoot, { recursive: true, mode: DIR_MODE });
  plainDir(colRoot);
  plainDir(strRoot);
  let closed2 = false;
  const open = () => {
    if (closed2) throw new EngineError("store_closed", "store is closed", 500);
  };
  const streams = /* @__PURE__ */ new Map();
  const streamPath = (s) => join(strRoot, `s_${encodeName(s)}.jsonl`);
  function scan(stream) {
    const path = streamPath(stream);
    if (!existsSync(path)) return { size: 0, good: 0, total: 0, lines: [] };
    const buf = readPlain(path);
    const end = buf.lastIndexOf(10);
    const good = end + 1;
    const text = buf.subarray(0, good).toString("utf8");
    const lines = good === 0 ? [] : text.slice(0, -1).split("\n");
    return { size: lines.length, good, total: buf.length, lines };
  }
  function state(stream) {
    let st = streams.get(stream);
    if (!st) {
      const s = scan(stream);
      st = { size: s.size, good: s.good, total: s.total };
      streams.set(stream, st);
    }
    return st;
  }
  return {
    get(collection, id) {
      open();
      checkName(collection, "collection");
      checkName(id);
      const p = join(colRoot, `c_${encodeName(collection)}`, `i_${encodeName(id)}.json`);
      if (!existsSync(join(colRoot, `c_${encodeName(collection)}`))) return null;
      plainDir(join(colRoot, `c_${encodeName(collection)}`));
      let buf;
      try {
        buf = readPlain(p);
      } catch (e) {
        if (e.code === "ENOENT") return null;
        throw e;
      }
      const r = record(buf.toString("utf8"));
      if (r.id !== id) throw new EngineError("store_corrupt", "record file holds a different id", 500);
      return r.value;
    },
    put(collection, id, value) {
      open();
      checkName(collection, "collection");
      checkName(id);
      toJson(value);
      const text = toJson({ id, value });
      const d = join(colRoot, `c_${encodeName(collection)}`);
      mkdirSync(d, { recursive: true, mode: DIR_MODE });
      plainDir(d);
      const final = join(d, `i_${encodeName(id)}.json`);
      const tmp = join(d, `.tmp-${randomBytes(8).toString("hex")}`);
      let fd;
      try {
        fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, FILE_MODE);
        writeAll(fd, Buffer.from(text, "utf8"));
        fsyncSync(fd);
        closeSync(fd);
        fd = void 0;
        renameSync(tmp, final);
        syncDir(d);
      } catch (e) {
        if (fd !== void 0) try {
          closeSync(fd);
        } catch {
        }
        try {
          unlinkSync(tmp);
        } catch {
        }
        throw e;
      }
    },
    list(collection) {
      open();
      checkName(collection, "collection");
      const d = join(colRoot, `c_${encodeName(collection)}`);
      if (!existsSync(d)) return [];
      plainDir(d);
      const rows = [];
      for (const f of readdirSync(d)) {
        if (!f.startsWith("i_") || !f.endsWith(".json")) continue;
        const r = record(readPlain(join(d, f)).toString("utf8"));
        if (`i_${encodeName(r.id)}.json` !== f) throw new EngineError("store_corrupt", "record file name does not match its id", 500);
        rows.push(r);
      }
      rows.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
      return rows.map((r) => r.value);
    },
    append(stream, value) {
      open();
      checkName(stream, "stream");
      const line = toJson(value) + "\n";
      const st = state(stream);
      const path = streamPath(stream);
      const created = !existsSync(path);
      const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | NOFOLLOW, FILE_MODE);
      try {
        if (!fstatSync(fd).isFile()) throw new EngineError("store_corrupt", "storage path is not a regular file", 500);
        if (fstatSync(fd).size !== st.total) {
          streams.delete(stream);
          throw new EngineError("store_conflict", `stream ${stream} was changed by another writer`, 500);
        }
        ftruncateSync(fd, st.good);
        const bytes = Buffer.from(line, "utf8");
        writeAll(fd, bytes, st.good);
        fsyncSync(fd);
        st.good += bytes.length;
        st.total = st.good;
      } finally {
        closeSync(fd);
      }
      if (created) syncDir(strRoot);
      return st.size++;
    },
    read(stream, from = 0, to) {
      open();
      checkName(stream, "stream");
      const s = scan(stream);
      const [f, t] = checkRange(from, to, s.size);
      return s.lines.slice(f, t).map((l) => {
        try {
          return fromJson(l);
        } catch {
          throw new EngineError("store_corrupt", `stream ${stream} has an unreadable line`, 500);
        }
      });
    },
    size(stream) {
      open();
      checkName(stream, "stream");
      const st = state(stream);
      const path = streamPath(stream);
      if (existsSync(path) && lstatSync(path).size !== st.total) streams.delete(stream);
      return state(stream).size;
    },
    /** Report streams whose last line is incomplete (crash during write). */
    verify() {
      open();
      const out = [];
      for (const f of readdirSync(strRoot)) {
        if (!f.startsWith("s_") || !f.endsWith(".jsonl")) continue;
        const buf = readPlain(join(strRoot, f));
        const good = buf.lastIndexOf(10) + 1;
        out.push({ file: f, size: good === 0 ? 0 : buf.subarray(0, good).toString("utf8").split("\n").length - 1, truncatedBytes: buf.length - good });
      }
      return { ok: out.every((s) => s.truncatedBytes === 0), streams: out };
    },
    close() {
      closed2 = true;
    }
  };
}

// engine/src/store/sqlite.mjs
function loadSqlite() {
  let mod = null;
  try {
    mod = process.getBuiltinModule?.("node:sqlite") ?? null;
  } catch {
    mod = null;
  }
  if (!mod || !mod.DatabaseSync) throw new EngineError("sqlite_unavailable", "node:sqlite is not available in this Node version", 500);
  return mod;
}
function sqliteAvailable() {
  try {
    loadSqlite();
    return true;
  } catch {
    return false;
  }
}
function createSqliteStore({ path = ":memory:", db = null, prefix = "sanad_" } = {}) {
  if (typeof prefix !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,30}$/.test(prefix)) throw new EngineError("bad_prefix", "invalid table prefix");
  const owned = !db;
  const conn = db || new (loadSqlite()).DatabaseSync(path);
  const kv = `${prefix}kv`, st = `${prefix}stream`;
  conn.exec(`CREATE TABLE IF NOT EXISTS ${kv}(collection TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(collection, id))`);
  conn.exec(`CREATE TABLE IF NOT EXISTS ${st}(stream TEXT NOT NULL, idx INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(stream, idx))`);
  const q = {
    get: conn.prepare(`SELECT value FROM ${kv} WHERE collection = ? AND id = ?`),
    put: conn.prepare(`INSERT INTO ${kv}(collection, id, value) VALUES(?, ?, ?) ON CONFLICT(collection, id) DO UPDATE SET value = excluded.value`),
    list: conn.prepare(`SELECT value FROM ${kv} WHERE collection = ? ORDER BY id`),
    size: conn.prepare(`SELECT COUNT(*) AS n FROM ${st} WHERE stream = ?`),
    append: conn.prepare(`INSERT INTO ${st}(stream, idx, value) VALUES(?, ?, ?)`),
    read: conn.prepare(`SELECT value FROM ${st} WHERE stream = ? AND idx >= ? AND idx < ? ORDER BY idx`)
  };
  let closed2 = false;
  const open = () => {
    if (closed2) throw new EngineError("store_closed", "store is closed", 500);
  };
  const size = (s) => Number(q.size.get(s).n);
  return {
    get(collection, id) {
      open();
      checkName(collection, "collection");
      checkName(id);
      const r = q.get.get(collection, id);
      return r ? fromJson(r.value) : null;
    },
    put(collection, id, value) {
      open();
      checkName(collection, "collection");
      checkName(id);
      q.put.run(collection, id, toJson(value));
    },
    list(collection) {
      open();
      checkName(collection, "collection");
      return q.list.all(collection).map((r) => fromJson(r.value));
    },
    append(stream, value) {
      open();
      checkName(stream, "stream");
      const text = toJson(value);
      const n = size(stream);
      q.append.run(stream, n, text);
      return n;
    },
    read(stream, from = 0, to) {
      open();
      checkName(stream, "stream");
      const [f, t] = checkRange(from, to, size(stream));
      return q.read.all(stream, f, t).map((r) => fromJson(r.value));
    },
    size(stream) {
      open();
      checkName(stream, "stream");
      return size(stream);
    },
    close() {
      if (closed2) return;
      closed2 = true;
      if (owned) conn.close();
    }
  };
}

// engine/src/store/index.mjs
function openStore(spec) {
  if (spec === "memory") return createMemoryStore();
  if (spec && typeof spec === "object") {
    if (spec.type === "memory") return createMemoryStore();
    if (spec.type === "file") return createFileStore(spec.dir);
    if (spec.type === "sqlite") return createSqliteStore({ path: spec.path, db: spec.db, prefix: spec.prefix });
  }
  throw new EngineError("bad_store", "unknown store specification");
}

// engine/src/bundle.mjs
import { randomUUID } from "node:crypto";
var DID_KEY2 = "did:key:";
var KINDS4 = ["auto", "sitting", "artifact", "peer"];
var ISO_DT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
var byId2 = (a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
var clone2 = (v) => JSON.parse(JSON.stringify(v));
var isObj4 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
var isStr3 = (v) => typeof v === "string";
var exactly2 = (o, names) => {
  if (!isObj4(o)) return false;
  const k = Object.keys(o).sort();
  const n = [...names].sort();
  return k.length === n.length && k.every((x, i) => x === n[i]);
};
var CREDENTIAL_TYP = "sanad-credential+jws";
var ATTESTATION_TYP = "sanad-attestation+jws";
function sealBundle({ skill, claimedLevel, subject, evidence, attestations, attestors }) {
  const atts = [];
  let prev = "GENESIS";
  for (const { statement: s, signature } of [...attestations].sort((a, b) => byId2(a.statement, b.statement))) {
    const base = { id: s.id, attestor: s.attestor, evidence: s.evidence, level: s.level, role: s.role, conflictDeclared: s.conflictDeclared, date: s.date, commit: s.commit, nonce: s.nonce, prev };
    const hash = attestationHashOf(base);
    atts.push({ ...base, signature, hash });
    prev = hash;
  }
  return clone2({ skill, claimedLevel, subject, evidence: [...evidence].sort(byId2), attestations: atts, attestors: attestors ?? {} });
}
function bundleHashOf(bundle) {
  return hashOf({
    alg: SANAD_VERSION,
    skill: bundle.skill,
    claimedLevel: bundle.claimedLevel,
    subject: bundle.subject,
    evidence: [...bundle.evidence].sort(byId2),
    attestations: [...bundle.attestations].sort(byId2)
  });
}
function buildCredential({ bundle, issuer, template, assessment, process: process2, policy, log, dids = [], now, id }) {
  const validFrom = new Date(now).toISOString();
  const bundleHash = bundleHashOf(bundle);
  const doc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "SanadCredential"],
    id: id ?? "urn:uuid:" + randomUUID(),
    issuer: issuer.did,
    validFrom,
    credentialSubject: { id: bundle.subject, skill: bundle.skill, claimedLevel: bundle.claimedLevel },
    evidence: [{ type: ["Evidence", "SanadBundle"], id: "urn:sanad:bundle:" + bundleHash, bundleHash, alg: SANAD_VERSION }],
    sanad: { bundle: clone2(bundle), template: { id: template.id, hash: template.hash }, assessment, process: clone2(process2), policy: clone2(policy), log: clone2(log), dids: clone2(dids) }
  };
  const jws = issuer.sign(CREDENTIAL_TYP, clone2(doc));
  return { ...doc, proof: { type: "SanadDetachedJws", verificationMethod: issuer.kid, created: validFrom, jws } };
}
var VERIFY_LIMITS = { attestations: 200, evidence: 200, logEntries: 2e3, dids: 100, versionsPerHistory: DID_LIMITS.versions, keysPerVersion: DID_LIMITS.keys, revokedPerVersion: DID_LIMITS.revoked };
var NOTICE = "Experimental software: the Sanad engine has not been cryptographically reviewed. A passing report records what was signed and logged, not that the attestors were honest. Backdating with a stolen attestor key, collusion and help off camera are not detected.";
var PROCESS_BASE = ["invited", "committed", "revealed", "missing", "late", "notCommitted"];
var processOk = (pr) => isObj4(pr) && PROCESS_BASE.every((k) => k in pr) && Object.keys(pr).every((k) => PROCESS_BASE.includes(k) || k === "removed" || k === "shortfall") && ["removed", "shortfall"].every((k) => !(k in pr) || Array.isArray(pr[k]) && pr[k].every(isStr3));
var POLICY_KEYS = ["minAttestors", "requireLive", "halfLifeMonths", "minAttestorSittings", "minAgreement", "maxInferenceDepth", "inferenceDecay"];
function shapeProblems(doc) {
  const p = [];
  const need = (cond, msg) => {
    if (!cond) p.push(msg);
  };
  if (!exactly2(doc, ["@context", "type", "id", "issuer", "validFrom", "credentialSubject", "evidence", "sanad", "proof"])) {
    p.push("top level members must be exactly @context, type, id, issuer, validFrom, credentialSubject, evidence, sanad, proof");
    return p;
  }
  need(canonical(doc["@context"]) === canonical(["https://www.w3.org/ns/credentials/v2"]), "@context is not the VC 2.0 context");
  need(canonical(doc.type) === canonical(["VerifiableCredential", "SanadCredential"]), "type is not VerifiableCredential, SanadCredential");
  need(isStr3(doc.id) && /^urn:uuid:[0-9a-f-]{36}$/.test(doc.id), "id is not a urn:uuid");
  need(isStr3(doc.issuer) && doc.issuer.startsWith("did:"), "issuer is not a DID");
  need(isStr3(doc.validFrom) && ISO_DT.test(doc.validFrom) && !Number.isNaN(Date.parse(doc.validFrom)), "validFrom is not an ISO date-time in UTC");
  need(exactly2(doc.credentialSubject, ["id", "skill", "claimedLevel"]), "credentialSubject members");
  need(Array.isArray(doc.evidence) && doc.evidence.length === 1 && exactly2(doc.evidence[0], ["type", "id", "bundleHash", "alg"]), "evidence must be one bundle reference with type, id, bundleHash, alg");
  need(exactly2(doc.proof, ["type", "verificationMethod", "created", "jws"]), "proof members");
  const s = doc.sanad;
  if (!exactly2(s, ["bundle", "template", "assessment", "process", "policy", "log", "dids"])) {
    p.push("sanad members must be exactly bundle, template, assessment, process, policy, log, dids");
    return p;
  }
  need(exactly2(s.template, ["id", "hash"]), "sanad.template members");
  need(isStr3(s.assessment), "sanad.assessment must be a string");
  need(processOk(s.process), "sanad.process members");
  need(exactly2(s.policy, ["id", ...POLICY_KEYS]), "sanad.policy members");
  need(Array.isArray(s.dids) && s.dids.every((d) => exactly2(d, ["id", "versions"]) && isStr3(d.id) && Array.isArray(d.versions)), "sanad.dids must be a list of { id, versions }");
  if (Array.isArray(s.dids)) {
    if (s.dids.length > VERIFY_LIMITS.dids) p.push("too many DID histories (limit " + VERIFY_LIMITS.dids + ")");
    for (const d of s.dids) {
      if (!isObj4(d) || !Array.isArray(d.versions)) continue;
      if (d.versions.length > VERIFY_LIMITS.versionsPerHistory) {
        p.push(`DID history ${String(d.id).slice(0, 60)} has more than ${VERIFY_LIMITS.versionsPerHistory} versions`);
        continue;
      }
      for (const v of d.versions) if (isObj4(v) && (Array.isArray(v.keys) && v.keys.length > VERIFY_LIMITS.keysPerVersion || Array.isArray(v.revoked) && v.revoked.length > VERIFY_LIMITS.revokedPerVersion)) {
        p.push(`a DID version has more than ${VERIFY_LIMITS.keysPerVersion} keys or ${VERIFY_LIMITS.revokedPerVersion} revocations`);
        break;
      }
    }
  }
  if (isObj4(s.log) && Array.isArray(s.log.entries) && s.log.entries.length > VERIFY_LIMITS.logEntries) {
    p.push("too many log entries (limit " + VERIFY_LIMITS.logEntries + ")");
    return p;
  }
  const l = s.log;
  need(exactly2(l, ["logId", "logKey", "entries", "proofs", "checkpoint"]) && Array.isArray(l.entries) && Array.isArray(l.proofs) && l.entries.every((e) => exactly2(e, ["index", "leaf"])) && l.proofs.every((e) => exactly2(e, ["index", "size", "proof"])) && exactly2(l.checkpoint, ["payload", "jws"]), "sanad.log members");
  const b = s.bundle;
  if (isObj4(b) && (Array.isArray(b.attestations) && b.attestations.length > VERIFY_LIMITS.attestations || Array.isArray(b.evidence) && b.evidence.length > VERIFY_LIMITS.evidence)) {
    p.push("too many evidence items or attestations (limits " + VERIFY_LIMITS.evidence + " and " + VERIFY_LIMITS.attestations + ")");
    return p;
  }
  if (!exactly2(b, ["skill", "claimedLevel", "subject", "evidence", "attestations", "attestors"])) {
    p.push("bundle members must be exactly skill, claimedLevel, subject, evidence, attestations, attestors");
    return p;
  }
  need(isStr3(b.skill) && isStr3(b.subject) && Number.isInteger(b.claimedLevel) && b.claimedLevel >= 0 && b.claimedLevel <= 5, "bundle skill, subject and claimedLevel (an integer from 0 to 5)");
  if (!Array.isArray(b.evidence) || !Array.isArray(b.attestations) || !isObj4(b.attestors)) {
    p.push("bundle evidence and attestations must be lists, attestors an object");
    return p;
  }
  b.evidence.forEach((e, i) => {
    if (!exactly2(e, ["id", "kind", "date", "summary", "body", "hash"])) p.push(`evidence[${i}] members must be exactly id, kind, date, summary, body, hash`);
    else if (!isStr3(e.id) || !KINDS4.includes(e.kind) || !isStr3(e.date) || !isStr3(e.summary) || !isObj4(e.body) || !isStr3(e.hash)) p.push(`evidence[${i}] member types`);
  });
  b.attestations.forEach((a, i) => {
    if (!exactly2(a, ["id", "attestor", "evidence", "level", "role", "conflictDeclared", "date", "signature", "commit", "nonce", "prev", "hash"])) p.push(`attestations[${i}] members must be exactly the twelve of the reference shape`);
    else if (!["id", "attestor", "evidence", "role", "date", "signature", "commit", "nonce", "prev", "hash"].every((k) => isStr3(a[k])) || !Number.isInteger(a.level) || typeof a.conflictDeclared !== "boolean") p.push(`attestations[${i}] member types`);
  });
  for (const [did, st] of Object.entries(b.attestors)) if (!exactly2(st, ["sittings", "agreement"]) || typeof st.sittings !== "number" || typeof st.agreement !== "number") p.push(`attestors.${did} must be { sittings, agreement }`);
  if (new Set(b.evidence.map((e) => e.id)).size !== b.evidence.length) p.push("duplicate evidence id");
  if (new Set(b.attestations.map((a) => a.id)).size !== b.attestations.length) p.push("duplicate attestation id");
  return p;
}
function verifierResolver(given, embeddedDids, trusted) {
  const mapOf = (list) => {
    const m = /* @__PURE__ */ new Map();
    for (const d of Array.isArray(list) ? list : []) if (isObj4(d) && isStr3(d.id)) m.set(d.id, d);
    return m;
  };
  const embMap = mapOf(embeddedDids), trMap = mapOf(trusted);
  const emb = createResolver({ store: { get: (c, id) => embMap.get(id) ?? null, put() {
  } } });
  const tr = createResolver({ store: { get: (c, id) => trMap.get(id) ?? null, put() {
  } } });
  const usedEmbedded = /* @__PURE__ */ new Map();
  const givenHas = /* @__PURE__ */ new Map();
  const has2 = (did) => {
    if (!givenHas.has(did)) {
      let h = false;
      try {
        h = !!(given && typeof given.get === "function" && isStr3(did) && !did.startsWith(DID_KEY2) && given.get(did));
      } catch {
        h = false;
      }
      givenHas.set(did, h);
    }
    return givenHas.get(did);
  };
  const pick = (did) => has2(did) ? { r: given, emb: false } : trMap.has(did) ? { r: tr, emb: false } : { r: emb, emb: true };
  return {
    usedEmbedded,
    keysAt(did, date) {
      try {
        return pick(did).r.keysAt(did, date);
      } catch {
        return [];
      }
    },
    verifyStatement(arg) {
      try {
        const { r, emb: isEmb } = pick(arg.signer);
        const res = r.verifyStatement(arg);
        if (res.ok && isEmb && !String(arg.signer).startsWith(DID_KEY2)) {
          const mb = res.publicKey ? "z" + base58btcEncode(res.publicKey) : "?";
          if (!usedEmbedded.has(arg.signer)) usedEmbedded.set(arg.signer, /* @__PURE__ */ new Set());
          usedEmbedded.get(arg.signer).add(mb);
        }
        return res;
      } catch {
        return { ok: false, reason: "bad_did_history" };
      }
    }
  };
}
var ADD = (checks, name, ok, detail) => checks.push({ name, ok, detail });
var isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);
function verifyCredential(doc, opts = {}) {
  const checks = [], warnings = [];
  let recognition = null, inferred = [], basis = null, unverifiedLabel = false;
  const done = () => {
    const ok = checks.every((c) => c.ok);
    return { ok, checks, recognition: recognition && !ok && unverifiedLabel ? { ...recognition, unverified: true } : recognition, inferred, warnings, basis, notice: NOTICE };
  };
  try {
    if (!isObj4(doc)) {
      ADD(checks, "shape", false, "the credential must be a JSON object");
      return done();
    }
    const problems = shapeProblems(doc);
    ADD(checks, "shape", problems.length === 0, problems.length ? problems.join("; ") : "closed member sets everywhere; no unknown members");
    if (problems.length) return done();
    const { sanad } = doc, bundle = sanad.bundle;
    const resolver = verifierResolver(opts.resolver, sanad.dids, opts.trustedDidHistories);
    const day = new Date(doc.validFrom).toISOString().slice(0, 10);
    {
      const { proof } = doc, { proof: _omit, ...body } = doc;
      const r = proof.type === "SanadDetachedJws" ? resolver.verifyStatement({ jws: proof.jws, payload: body, typ: CREDENTIAL_TYP, signer: doc.issuer, date: day }) : { ok: false, reason: "unknown_proof_type" };
      const kidOk = r.ok && r.kid === proof.verificationMethod;
      const proofOk = r.ok && kidOk && proof.created === doc.validFrom;
      ADD(
        checks,
        "issuer-proof",
        proofOk,
        r.ok ? kidOk ? proof.created === doc.validFrom ? `signed by ${r.kid}, valid on ${day}` : "proof.created differs from validFrom" : "verificationMethod differs from the signing key" : "issuer signature refused: " + r.reason
      );
      if (!proofOk && opts.diagnose !== true) {
        warnings.push("verification stopped at the failed issuer proof; pass diagnose to examine the rest");
        return done();
      }
    }
    {
      const h = bundleHashOf(bundle), ref = doc.evidence[0];
      const why = [];
      if (h !== ref.bundleHash) why.push(`recomputed ${h} differs from evidence[0].bundleHash`);
      if (ref.id !== "urn:sanad:bundle:" + ref.bundleHash) why.push("evidence[0].id does not name the bundle hash");
      if (ref.alg !== SANAD_VERSION) why.push("alg is not " + SANAD_VERSION);
      if (canonical(doc.credentialSubject) !== canonical({ id: bundle.subject, skill: bundle.skill, claimedLevel: bundle.claimedLevel })) why.push("credentialSubject differs from the bundle");
      ADD(checks, "bundle-hash", why.length === 0, why.length ? why.join("; ") : "bundle hash " + h);
    }
    {
      const bad2 = bundle.evidence.filter((e) => e.body.kind !== e.kind || e.body.date !== e.date).map((e) => e.id);
      ADD(checks, "evidence-consistency", bad2.length === 0, bad2.length ? "kind or date differs from the hashed body in: " + bad2.join(", ") : "kind and date equal the hashed body in every evidence item");
    }
    {
      const pre = sanad.assessment + ".";
      const bad2 = [...bundle.evidence.map((e) => e.id), ...bundle.attestations.map((a) => a.id)].filter((id) => !id.startsWith(pre));
      ADD(checks, "ids", bad2.length === 0, bad2.length ? `ids outside assessment ${sanad.assessment}: ${bad2.slice(0, 5).join(", ")}` : "every evidence and attestation id belongs to assessment " + sanad.assessment);
    }
    const sigCache = /* @__PURE__ */ new Map();
    const sigReason = (a) => {
      if (sigCache.has(a.id)) return sigCache.get(a.id);
      const { prev: _p, ...stmt } = attestationPayload(a);
      const r = resolver.verifyStatement({ jws: a.signature, payload: stmt, typ: ATTESTATION_TYP, signer: a.attestor, date: a.date });
      sigCache.set(a.id, r);
      return r;
    };
    {
      const bad2 = [];
      for (const a of bundle.attestations) {
        const r = sigReason(a);
        if (!r.ok) bad2.push(`${a.id} (${r.reason})`);
      }
      ADD(checks, "attestor-signatures", bad2.length === 0, bad2.length ? "signature refused: " + bad2.join(", ") : `${bundle.attestations.length} attestor signature(s) verify on their dates`);
    }
    {
      const l = sanad.log, why = [];
      const cp = l.checkpoint;
      const sigOk = verifyCheckpoint(cp, (jws, payload, typ) => resolver.verifyStatement({ jws, payload, typ, signer: l.logKey, date: String(payload.timestamp).slice(0, 10) }).ok);
      if (!sigOk) why.push("checkpoint signature does not verify with the log key");
      if (sigOk && cp.payload.logId !== l.logId) why.push("checkpoint logId differs from the log id");
      if (Array.isArray(opts.trustedLogIds) && !opts.trustedLogIds.includes(l.logId)) why.push("log id " + l.logId + " is not among the trusted log ids");
      const leaves = /* @__PURE__ */ new Map();
      if (sigOk) {
        for (const e of l.entries) {
          let parsed;
          try {
            parsed = JSON.parse(e.leaf);
            leafBytes(parsed);
            if (canonical(parsed) !== e.leaf) throw new Error("not canonical");
          } catch {
            why.push(`entry ${e.index}: the leaf is not a valid canonical leaf`);
            continue;
          }
          const pr = l.proofs.find((x) => x.index === e.index);
          if (!pr || pr.size !== cp.payload.size) {
            why.push(`entry ${e.index}: no inclusion proof for the checkpoint size`);
            continue;
          }
          if (!verifyInclusion({ leafHash: leafHash(e.leaf), index: e.index, size: pr.size, proof: pr.proof, root: cp.payload.rootHash })) {
            why.push(`entry ${e.index}: inclusion proof does not match the checkpoint root`);
            continue;
          }
          leaves.set(parsed.kind + ":" + parsed.ref, true);
        }
        for (const a of bundle.attestations) if (!leaves.has("attestation:" + a.hash)) why.push(`attestation ${a.id} is not a verified leaf of the log`);
        if (!leaves.has("bundle:" + doc.evidence[0].bundleHash)) why.push("the bundle hash is not a verified leaf of the log");
      }
      ADD(checks, "log", why.length === 0, why.length ? why.join("; ") : `${l.entries.length} embedded entr${l.entries.length === 1 ? "y" : "ies"} verified against the checkpoint of size ${cp.payload.size}; every attestation hash and the bundle hash are leaves`);
    }
    const pin = (name, label, list, value) => {
      if (Array.isArray(list)) {
        const ok = list.includes(value);
        ADD(checks, name, ok, ok ? `${label} is pinned: ${value}` : `${label} ${value} is not among the pinned ${label}s`);
      } else if (opts.allowUnpinned === true) {
        ADD(checks, name, true, `${label} not pinned (allowUnpinned): ${value}`);
        warnings.push(`${label} not pinned`);
      } else ADD(checks, name, false, `${label} ${value} is not pinned: pass ${name === "trusted-issuer" ? "trustedIssuers" : "trustedLogKeys"}, or allowUnpinned to accept any`);
    };
    pin("trusted-issuer", "issuer", opts.trustedIssuers, doc.issuer);
    pin("trusted-log-key", "log key", opts.trustedLogKeys, sanad.log.logKey);
    if (resolver.usedEmbedded.size) {
      const pinned = isObj4(opts.pinnedKeys) ? opts.pinnedKeys : {};
      const bad2 = [];
      for (const [did, keys] of resolver.usedEmbedded) for (const k of keys) if (!(Array.isArray(pinned[did]) && pinned[did].includes(k))) bad2.push(`${did} (key ${k.slice(0, 12)}...)`);
      if (bad2.length && opts.allowEmbeddedDids === true) {
        warnings.push("DID histories embedded in the credential were trusted (allowEmbeddedDids): " + bad2.join(", "));
        ADD(checks, "did-histories", true, "embedded did histories accepted without pinned keys (allowEmbeddedDids)");
      } else {
        if (bad2.length) warnings.push("embedded DID histories are the issuer's own claim; pin the keys (pinnedKeys) or supply the histories (trustedDidHistories): " + bad2.join(", "));
        ADD(checks, "did-histories", bad2.length === 0, bad2.length ? "keys known only from histories embedded in the credential and not pinned by the verifier: " + bad2.join(", ") : "every did:web key used is pinned by the verifier");
      }
    }
    {
      const pr = sanad.process, n = bundle.attestations.length, why = [];
      if (pr.revealed !== n) why.push(`process.revealed is ${pr.revealed} but the bundle has ${n} attestation(s)`);
      if (pr.committed < pr.revealed || pr.committed > pr.invited) why.push("process counts are inconsistent (revealed <= committed <= invited must hold)");
      if (pr.missing.length !== pr.committed - pr.revealed) why.push("process.missing does not account for committed minus revealed");
      if (pr.notCommitted.length !== pr.invited - pr.committed) why.push("process.notCommitted does not account for invited minus committed");
      if (pr.late.some((id) => !pr.missing.includes(id))) why.push("process.late names an attestation that is not missing");
      const have = new Set(bundle.attestations.map((a) => a.id));
      if (pr.missing.some((id) => have.has(id))) why.push("process.missing names an attestation that is in the bundle");
      ADD(checks, "process", why.length === 0, why.length ? why.join("; ") : "process counts agree with the bundle");
    }
    if (opts.template !== void 0) {
      const why = [];
      try {
        const t = opts.template;
        if (templateHash(t) !== sanad.template.hash) why.push("the supplied template does not have the credential's template hash");
        if (t.id !== sanad.template.id) why.push("template id differs");
        const roles = t.attestors?.roles ?? [];
        for (const a of bundle.attestations) if (!roles.includes(a.role)) why.push(`attestation ${a.id} has role "${a.role}", which the template does not list`);
        const kinds = new Map((t.evidence ?? []).map((e) => [sanad.assessment + "." + e.key, e.kind]));
        for (const e of bundle.evidence) if (kinds.get(e.id) !== e.kind) why.push(`evidence ${e.id} is not an item of kind ${e.kind} of the template`);
        const have = new Set(bundle.evidence.map((e) => e.id));
        for (const id of kinds.keys()) if (!have.has(id)) why.push(`the template's evidence item ${id} is missing from the credential`);
        const short = [];
        const per = new Map(bundle.evidence.map((e) => [e.id, /* @__PURE__ */ new Set()]));
        for (const a of bundle.attestations) if (!a.conflictDeclared) per.get(a.evidence)?.add(a.attestor);
        for (const e of bundle.evidence) if (e.kind !== "auto" && per.get(e.id).size < (t.attestors?.min ?? 1)) short.push(e.id);
        if (t.liveSitting && !bundle.evidence.some((e) => e.kind === "sitting" && per.get(e.id).size > 0)) short.push("liveSitting");
        if (short.length && !(Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length)) why.push("below the template minimum (" + short.join(", ") + ") and the credential records no process.shortfall");
      } catch {
        why.push("the supplied template is not usable");
      }
      ADD(checks, "template", why.length === 0, why.length ? why.join("; ") : "template hash, roles and evidence kinds match");
    } else warnings.push("template not supplied: roles and evidence kinds were not checked against it");
    if (Array.isArray(sanad.process.shortfall) && sanad.process.shortfall.length) warnings.push("the operator finalized below the template minimum: " + sanad.process.shortfall.join("; "));
    let pol = null, polSource = null, asOfSource = null;
    if (opts.policy !== void 0) {
      pol = isObj4(opts.policy) ? { ...opts.policy } : opts.policy;
      polSource = "verifier";
    } else if (opts.useRecommendedPolicy === true) {
      pol = { ...sanad.policy };
      delete pol.id;
      polSource = "issuer-recommendation";
    }
    if (isObj4(pol)) {
      if (pol.asOf !== void 0) asOfSource = "policy";
      else if (opts.asOf !== void 0) {
        pol.asOf = opts.asOf;
        asOfSource = "option";
      } else if (opts.useVerifierClock === true) {
        pol.asOf = isoDay(opts.now ?? Date.now());
        asOfSource = "verifier-clock";
      } else if (polSource === "issuer-recommendation") {
        pol.asOf = day;
        asOfSource = "credential-date";
      }
    }
    if (pol === null) ADD(checks, "policy", false, "no verifier policy supplied: pass policy (all seven fields and asOf), or useRecommendedPolicy to take the issuer's recommendation knowingly");
    else {
      const pp = validatePolicy(pol);
      ADD(checks, "policy", pp.length === 0, pp.length ? "policy refused: " + pp.join("; ") : `${polSource} policy; evaluation day ${pol.asOf} (${asOfSource})`);
      if (pp.length === 0) {
        basis = { policySource: polSource === "verifier" ? "verifier" : "issuer-recommendation", asOfSource };
        const own = opts.attestorStats;
        if (own !== void 0) {
          const okShape = isObj4(own) && Object.values(own).every((st) => isObj4(st) && Number.isFinite(st.sittings) && Number.isFinite(st.agreement));
          ADD(checks, "attestor-statistics", okShape, okShape ? "verifier-supplied statistics replace the issuer's" : "attestorStats must map DIDs to { sittings, agreement }");
        } else if (pol.minAttestorSittings > 0 || pol.minAgreement > 0) {
          const allow = opts.allowIssuerStatistics === true;
          ADD(checks, "attestor-statistics", allow, allow ? "issuer-supplied statistics used for a threshold (allowIssuerStatistics)" : "the policy has a statistics threshold but the only statistics are the issuer's, which no verifier can recompute from the log: pass attestorStats, or allowIssuerStatistics");
          if (allow) warnings.push("issuer-supplied statistics used for a threshold; they are not recomputable from the hash-only log");
        }
        try {
          const cred = isObj4(own) ? { ...bundle, attestors: own } : bundle;
          const ropts = { verifySignature: (a) => sigReason(a).ok };
          if (Array.isArray(opts.allowedAttestors)) ropts.allowAttestor = (d) => opts.allowedAttestors.includes(d);
          recognition = recognise(cred, pol, ropts);
          unverifiedLabel = true;
          if (opts.graph && recognition.status !== "not-recognised") inferred = infer(opts.graph, bundle.skill, recognition.level, recognition.confidence, pol, [bundle.skill]);
        } catch (e) {
          ADD(checks, "recognition", false, "the recognition function refused the input: " + (e?.message ?? e));
        }
      }
    }
  } catch (e) {
    ADD(checks, "internal", false, "verification failed unexpectedly: " + (e?.message ?? e));
  }
  return done();
}

// engine/src/attestor.mjs
function fromTicket(t) {
  return { id: t.assessment, templateHash: t.templateHash, invitations: [{ attestationId: t.attestationId, attestor: t.attestor, role: t.role, evidence: t.evidence }] };
}
var viewOf = (assessment, ticket) => ticket ? fromTicket(ticket) : assessment;
function invitationOf(assessment, attestationId, signer) {
  const inv2 = (assessment?.invitations ?? []).find((i) => i.attestationId === attestationId);
  if (!inv2) throw new EngineError("not_invited", "the assessment has no invitation " + attestationId, 403);
  if (inv2.attestor !== signer.did) throw new EngineError("not_invited", "the invitation " + attestationId + " is for " + inv2.attestor + ", not for " + signer.did, 403);
  return inv2;
}
function prepareCommit({ signer, assessment, ticket, attestationId, level, native, levelMap, nonce }) {
  assessment = viewOf(assessment, ticket);
  attestationId ??= ticket?.attestationId;
  levelMap ??= ticket?.levelMap;
  const inv2 = invitationOf(assessment, attestationId, signer);
  if (native !== void 0) {
    const mapped = levelFromNative(levelMap, native);
    if (level !== void 0 && level !== mapped) throw new EngineError("native_mismatch", "level and native mark disagree");
    level = mapped;
    nonce ??= nonceWithNative(native, newNonce());
  }
  if (!Number.isInteger(level) || level < 0 || level > 5) throw new EngineError("bad_level", "level must be an integer from 0 to 5");
  const n = nonce ?? newNonce();
  if (!NONCE_RE.test(n)) throw new EngineError("bad_nonce", "nonce must be 22 to 128 base64url characters");
  const commit = commitFor({ attestor: inv2.attestor, evidence: inv2.evidence, level, nonce: n });
  const payload = commitStatement({ assessment: assessment.id, attestationId, attestor: inv2.attestor, evidence: inv2.evidence, role: inv2.role, commit, templateHash: assessment.templateHash });
  return { request: { attestationId, payload, jws: signer.sign("sanad-commit+jws", payload) }, secret: { attestationId, level, nonce: n } };
}
function prepareReveal({ signer, assessment, ticket, attestationId, secret, date, conflictDeclared = false }) {
  assessment = viewOf(assessment, ticket);
  attestationId ??= ticket?.attestationId;
  const inv2 = invitationOf(assessment, attestationId, signer);
  if (!secret || secret.attestationId !== attestationId) throw new EngineError("bad_secret", "the secret does not belong to " + attestationId);
  const commit = commitFor({ attestor: inv2.attestor, evidence: inv2.evidence, level: secret.level, nonce: secret.nonce });
  const statement = attestationStatement({ id: attestationId, attestor: inv2.attestor, evidence: inv2.evidence, level: secret.level, role: inv2.role, conflictDeclared, date, commit, nonce: secret.nonce });
  return { attestationId, statement, jws: signer.sign("sanad-attestation+jws", statement) };
}

// engine/src/engine.mjs
import { randomBytes as randomBytes2, createHash as createHash3 } from "node:crypto";

// engine/src/ijson.mjs
var MAX_DEPTH = 64;
var bad = (code, message) => new EngineError(code, message, 400);
var LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function scanJsonText(text, { maxDepth = MAX_DEPTH } = {}) {
  let depth = 0, inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++;
      else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) {
      inStr = true;
      continue;
    }
    if (c === 91 || c === 123) {
      if (++depth > maxDepth) throw bad("too_deep", "JSON nesting is deeper than " + maxDepth);
      continue;
    }
    if (c === 93 || c === 125) {
      depth--;
      continue;
    }
    if (c === 45 || c >= 48 && c <= 57) {
      let j = i + 1;
      while (j < text.length) {
        const d = text.charCodeAt(j);
        if (d >= 48 && d <= 57 || d === 46 || d === 101 || d === 69 || d === 43 || d === 45) j++;
        else break;
      }
      const tok = text.slice(i, j), n = Number(tok);
      if (!Number.isFinite(n)) throw bad("bad_number", "a number is not finite: " + tok.slice(0, 20));
      if (/^-?\d+$/.test(tok) && !Number.isSafeInteger(n)) throw bad("bad_number", "an integer beyond 2^53 cannot be represented exactly: " + tok.slice(0, 20));
      i = j - 1;
    }
  }
}
function checkIJson(v, { maxDepth = MAX_DEPTH } = {}) {
  const walk = (x, d) => {
    if (d > maxDepth) throw bad("too_deep", "nesting is deeper than " + maxDepth);
    if (typeof x === "string") {
      if (LONE.test(x)) throw bad("bad_string", "a string holds a lone surrogate");
      return;
    }
    if (typeof x === "number") {
      if (!Number.isFinite(x)) throw bad("bad_number", "a number is not finite");
      if (Number.isInteger(x) && !Number.isSafeInteger(x)) throw bad("bad_number", "an integer beyond 2^53");
      return;
    }
    if (x === null || typeof x === "boolean") return;
    if (Array.isArray(x)) {
      for (const y of x) walk(y, d + 1);
      return;
    }
    if (typeof x === "object") {
      for (const k of Object.keys(x)) {
        if (LONE.test(k)) throw bad("bad_string", "a key holds a lone surrogate");
        walk(x[k], d + 1);
      }
      return;
    }
    throw bad("bad_json", "a value of type " + typeof x + " is not JSON");
  };
  walk(v, 0);
  return v;
}

// engine/src/engine.mjs
var ID_RE2 = /^[A-Za-z0-9._:-]{1,200}$/;
var SUBJECT_RE = /^urn:([a-z0-9][a-z0-9-]{0,31}):([^\s]{1,160})$/i;
var PERSONAL_NS = /* @__PURE__ */ new Set(["email", "mailto", "mail", "person", "name", "tel", "phone", "msisdn"]);
var subjectOk = (s) => {
  const m = typeof s === "string" ? SUBJECT_RE.exec(s) : null;
  return !!m && !PERSONAL_NS.has(m[1].toLowerCase()) && !m[2].includes("@");
};
var has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
var uuidFrom = (text) => {
  const h = createHash3("sha256").update(text).digest("hex");
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
var DID_KEY3 = "did:key:";
var COMMIT_TYP = "sanad-commit+jws";
var HOUR = 36e5;
var err = (code, message, status = 400) => new EngineError(code, message, status);
var clone3 = (v) => JSON.parse(JSON.stringify(v));
var isDateTime = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s) && !Number.isNaN(Date.parse(s));
function createEngine({ store, issuer, logSigner, logId = "sanad-log", resolver, clock = { now: () => Date.now() } } = {}) {
  if (!store) throw err("bad_config", "a store is required");
  if (!issuer || !issuer.did || !issuer.kid || typeof issuer.sign !== "function") throw err("bad_config", "issuer must be { did, kid, sign }");
  if (!logSigner || !logSigner.did || typeof logSigner.sign !== "function") throw err("bad_config", "logSigner must be { did, kid, sign }");
  const res = resolver ?? createResolver({ store });
  const log = createLog({ store, logId, signer: logSigner, clock });
  let hi = 0;
  const nowMs = () => {
    const t = clock.now();
    if (Number.isFinite(t) && t > hi) hi = t;
    return hi;
  };
  const nowIso = () => new Date(nowMs()).toISOString();
  const today = () => nowIso().slice(0, 10);
  const getRec = (id) => {
    const a = typeof id === "string" && ID_RE2.test(id) ? store.get("assessments", id) : null;
    if (!a) throw err("assessment_unknown", "no such assessment: " + id, 404);
    if (Number.isFinite(a.hwm) && a.hwm > hi) hi = a.hwm;
    return a;
  };
  const save = (a) => {
    a.hwm = Math.max(hi, a.hwm ?? 0);
    store.put("assessments", a.id, a);
  };
  const revealOpen = (a) => !!a.revealOpenedAt || Object.keys(a.reveals).length > 0 || a.invitations.length > 0 && a.invitations.every((i) => a.commits[i.attestationId]) || nowMs() > Date.parse(a.commitBy);
  const sigFail = (r) => {
    const e = err("bad_signature", "signature refused: " + r.reason, 401);
    e.reason = r.reason;
    return e;
  };
  function publicView(a) {
    const open = revealOpen(a) || a.state === "finalized";
    const commits = {};
    for (const [k, c] of Object.entries(a.commits)) commits[k] = { commit: c.commit, payload: c.payload, jws: c.jws, at: c.at };
    const reveals = {};
    if (open) for (const [k, r] of Object.entries(a.reveals)) reveals[k] = { statement: r.statement, jws: r.jws, at: r.at };
    const { id, templateId, templateHash: th, subject, claimedLevel, evidence, commitBy, revealBy, createdAt, invitations, late, state, credentialId } = a;
    return clone3({ id, templateId, templateHash: th, subject, claimedLevel, evidence, commitBy, revealBy, createdAt, invitations, removed: a.removed ?? [], commits, reveals, late, state, credentialId: credentialId ?? null, revealOpen: open });
  }
  let statsMemo = null;
  const finalizedStats = (excludeId) => {
    if (excludeId === void 0 || excludeId === null) {
      if (statsMemo) return statsMemo;
    }
    const records = [];
    for (const a of store.list("assessments")) {
      if (a.state !== "finalized" || a.id === excludeId) continue;
      const c = store.get("credentials", a.credentialId);
      if (!c) continue;
      const b = c.sanad.bundle;
      records.push({ evidence: b.evidence.map((e) => ({ id: e.id, kind: e.kind })), marks: b.attestations.map((x) => ({ attestor: x.attestor, evidence: x.evidence, level: x.level })) });
    }
    const out = attestorStats(records);
    if (excludeId === void 0 || excludeId === null) statsMemo = out;
    return out;
  };
  const engine = {
    registerTemplate(t) {
      checkIJson(t);
      assertTemplate(t);
      const hash = templateHash(t);
      const old = store.get("templates", t.id);
      if (old) {
        if (old.hash !== hash) throw err("template_exists", "template " + t.id + " exists with a different hash", 409);
        return { id: t.id, hash };
      }
      store.put("templates", t.id, { template: clone3(t), hash });
      return { id: t.id, hash };
    },
    getTemplate(id) {
      const r = typeof id === "string" && ID_RE2.test(id) ? store.get("templates", id) : null;
      if (!r) throw err("template_unknown", "no such template: " + id, 404);
      return clone3(r.template);
    },
    listTemplates() {
      return store.list("templates").map((r) => ({ id: r.template.id, hash: r.hash, title: r.template.title, version: r.template.version }));
    },
    registerDid(doc) {
      return res.register(doc);
    },
    updateDid(did, version, jws) {
      return res.update(did, version, jws);
    },
    createAssessment({ templateId, subject, subjectDid, claimedLevel, evidence, commitBy, revealBy, id } = {}) {
      const rec = typeof templateId === "string" && ID_RE2.test(templateId) ? store.get("templates", templateId) : null;
      if (!rec) throw err("template_unknown", "no such template: " + templateId, 404);
      const t = rec.template;
      if (!subjectOk(subject)) throw err("bad_subject", "subject must be a pseudonymous URN such as urn:uuid:<uuid> (no spaces, no personal namespace such as email, person, name or tel); names and contact details do not belong in the engine. This is a guard rail: the host remains responsible for choosing a non-identifying URN");
      if (subjectDid !== void 0 && !(typeof subjectDid === "string" && /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(subjectDid) && subjectDid.length <= 200)) throw err("bad_subject", "subjectDid must be a DID");
      if (!Number.isInteger(claimedLevel) || claimedLevel < 0 || claimedLevel > 5) throw err("bad_assessment", "claimedLevel must be an integer from 0 to 5");
      const aid = id ?? "as-" + randomBytes2(8).toString("hex");
      if (typeof aid !== "string" || !ID_RE2.test(aid) || aid.length > 150) throw err("bad_assessment", "id must match " + ID_RE2 + " and be at most 150 characters");
      if (store.get("assessments", aid)) throw err("assessment_exists", "assessment exists: " + aid, 409);
      if (!Array.isArray(evidence)) throw err("bad_evidence", "evidence must be a list");
      checkIJson(evidence);
      const plan = new Map(t.evidence.map((e) => [e.key, e]));
      const keys = evidence.map((e) => e?.key);
      if (keys.length !== plan.size || new Set(keys).size !== keys.length || !keys.every((k) => plan.has(k))) throw err("bad_evidence", "evidence keys must be exactly " + [...plan.keys()].join(", "));
      const sealed = [];
      for (const e of evidence) {
        if (e === null || typeof e !== "object" || Array.isArray(e)) throw err("bad_evidence", "an evidence item must be an object");
        if (!isIsoDate(e.date)) throw err("bad_evidence", "evidence " + e.key + ": date must be YYYY-MM-DD");
        if (typeof e.summary !== "string") throw err("bad_evidence", "evidence " + e.key + ": summary must be a string");
        if (e.body === null || typeof e.body !== "object" || Array.isArray(e.body)) throw err("bad_evidence", "evidence " + e.key + ": body must be an object");
        const kind = plan.get(e.key).kind;
        if ("kind" in e.body && e.body.kind !== kind || "date" in e.body && e.body.date !== e.date) throw err("bad_evidence", "evidence " + e.key + ": body.kind and body.date must equal the item kind and date");
        if (kind === "auto" && !(Number.isInteger(e.body.autoLevel) && e.body.autoLevel >= 0 && e.body.autoLevel <= 5)) throw err("bad_evidence", "evidence " + e.key + ": an automatic record needs body.autoLevel, an integer from 0 to 5 (the level a replay yields); without it the recognition function ignores the item");
        const body = { ...clone3(e.body), kind, date: e.date };
        sealed.push(sealEvidence({ id: `${aid}.${e.key}`, kind, date: e.date, summary: e.summary, body }));
      }
      const start = nowMs();
      const cb = commitBy === void 0 ? start + t.deadlines.commitHours * HOUR : isDateTime(commitBy) ? Date.parse(commitBy) : NaN;
      if (Number.isNaN(cb)) throw err("bad_assessment", "commitBy must be an ISO date-time");
      const rb = revealBy === void 0 ? cb + t.deadlines.revealHours * HOUR : isDateTime(revealBy) ? Date.parse(revealBy) : NaN;
      if (Number.isNaN(rb)) throw err("bad_assessment", "revealBy must be an ISO date-time");
      if (!(rb > cb)) throw err("bad_assessment", "revealBy must be after commitBy");
      const a = {
        id: aid,
        templateId,
        templateHash: rec.hash,
        subject,
        ...subjectDid ? { subjectDid } : {},
        claimedLevel,
        evidence: sealed,
        commitBy: new Date(cb).toISOString(),
        revealBy: new Date(rb).toISOString(),
        createdAt: nowIso(),
        invitations: [],
        commits: {},
        reveals: {},
        late: [],
        state: "open",
        credentialId: null
      };
      save(a);
      return publicView(a);
    },
    invite(assessmentId, { attestor, role, evidence } = {}) {
      const a = getRec(assessmentId);
      const t = engine.getTemplate(a.templateId);
      if (a.state !== "open") throw err("state", "the assessment is finalized", 409);
      if (revealOpen(a)) throw err("state", "the reveal phase is open; no more invitations", 409);
      const ev = a.evidence.find((e) => e.id === evidence || e.id === `${a.id}.${evidence}`);
      if (!ev) throw err("bad_evidence", "unknown evidence item: " + evidence);
      if (typeof attestor !== "string" || !/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/.test(attestor) || attestor.length > 200) throw err("bad_attestor", "attestor must be a DID");
      if (!t.attestors.roles.includes(role)) throw err("bad_role", "role must be one of " + t.attestors.roles.join(", "));
      if (a.subjectDid && attestor === a.subjectDid) throw err("subject_as_attestor", "the subject cannot attest their own work");
      const same = a.invitations.filter((i) => i.evidence === ev.id);
      if (same.some((i) => i.attestor === attestor)) throw err("duplicate_attestor", "this attestor is already invited on " + ev.id, 409);
      const seq = (a.seq ?? a.invitations.length) + 1;
      if (same.length >= t.attestors.max || seq > 99) throw err("too_many_attestors", "at most " + t.attestors.max + " attestors per evidence item", 409);
      if (res.keysAt(attestor, today()).length === 0) throw err("did_unresolvable", "no valid key for " + attestor + " today");
      const inv2 = { attestationId: `${a.id}.a${String(seq).padStart(2, "0")}`, attestor, role, evidence: ev.id, invitedAt: nowIso() };
      a.invitations.push(inv2);
      a.seq = seq;
      save(a);
      return clone3(inv2);
    },
    /** Operator action: withdraw an invitation before that attestor's first commit. Never reuses the attestation id; recorded in the events stream and in the credential's process.removed. */
    removeInvitation(assessmentId, attestationId, { reason } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== "open") throw err("state", "the assessment is finalized", 409);
      const i = a.invitations.findIndex((x) => x.attestationId === attestationId);
      if (i < 0) throw err("not_invited", "no invitation " + attestationId, 404);
      if (a.commits[attestationId]) throw err("already_committed", "a commit for " + attestationId + " exists; an invitation cannot be removed after the first commit", 409);
      if (reason !== void 0 && (typeof reason !== "string" || reason.length > 200)) throw err("bad_reason", "reason must be a string of up to 200 characters");
      const [inv2] = a.invitations.splice(i, 1);
      (a.removed ??= []).push({ attestationId, attestor: inv2.attestor, role: inv2.role, evidence: inv2.evidence, removedAt: nowIso() });
      store.append("events", { type: "invitation-removed", assessment: a.id, attestationId, attestor: inv2.attestor, at: nowIso(), ...reason ? { reason } : {} });
      save(a);
      return { removed: attestationId, invited: a.invitations.length };
    },
    commit(assessmentId, { attestationId, payload, jws } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== "open") throw err("state", "the assessment is finalized", 409);
      const inv2 = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv2) throw err("not_invited", "no invitation " + attestationId, 403);
      if (a.commits[attestationId]) throw err("already_committed", "a commit for " + attestationId + " exists", 409);
      if (a.revealOpenedAt || Object.keys(a.reveals).length > 0 || nowMs() > Date.parse(a.commitBy)) throw err("commit_closed", "the commit phase is over (deadline " + a.commitBy + " or reveals have begun)", 409);
      checkCommit({ payload, invitation: inv2, assessment: a });
      const r = res.verifyStatement({ jws, payload, typ: COMMIT_TYP, signer: inv2.attestor, date: today() });
      if (!r.ok) throw sigFail(r);
      const entry = log.append({ kind: "commit", ref: hashOf(payload) });
      a.commits[attestationId] = { commit: payload.commit, payload: clone3(payload), jws, at: nowIso(), logIndex: entry.index };
      if (a.invitations.every((i) => a.commits[i.attestationId])) a.revealOpenedAt = nowIso();
      save(a);
      return { committed: Object.keys(a.commits).length, of: a.invitations.length };
    },
    reveal(assessmentId, { attestationId, statement, jws } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== "open") throw err("state", "the assessment is finalized", 409);
      const inv2 = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv2) throw err("not_invited", "no invitation " + attestationId, 403);
      if (!revealOpen(a)) throw err("reveal_not_open", "the reveal phase is not open yet", 409);
      const c = a.commits[attestationId];
      if (!c) throw err("not_committed", "no commit for " + attestationId, 409);
      if (a.reveals[attestationId]) throw err("already_revealed", attestationId + " is already revealed", 409);
      if (nowMs() > Date.parse(a.revealBy)) {
        if (statement === null || typeof statement !== "object" || statement.id !== attestationId || statement.attestor !== inv2.attestor || !isIsoDate(statement.date)) throw err("bad_statement", "a late reveal is recorded only for a statement of the invited attestor");
        const lr = res.verifyStatement({ jws, payload: statement, typ: ATTESTATION_TYP, signer: inv2.attestor, date: statement.date });
        if (!lr.ok) throw sigFail(lr);
        if (!a.late.includes(attestationId)) {
          a.late.push(attestationId);
          a.late.sort();
          save(a);
        }
        throw err("reveal_late", "the reveal phase ended at " + a.revealBy, 409);
      }
      const t = engine.getTemplate(a.templateId);
      checkReveal({
        statement,
        invitation: inv2,
        storedCommit: c.commit,
        evidenceDate: a.evidence.find((e) => e.id === inv2.evidence).date,
        revealDay: today(),
        allowedLevels: t.levels.map((l) => l.level)
      });
      const nat = nativeOfNonce(statement.nonce);
      if (nat !== null && t.levelMap) {
        if (!Object.hasOwn(t.levelMap, nat)) throw err("native_unknown", "the nonce names a native mark that the template levelMap does not list");
        if (t.levelMap[nat] !== statement.level) throw err("native_mismatch", "the native mark in the nonce maps to a different level than the revealed level");
      }
      const r = res.verifyStatement({ jws, payload: statement, typ: ATTESTATION_TYP, signer: inv2.attestor, date: statement.date });
      if (!r.ok) throw sigFail(r);
      a.reveals[attestationId] = { statement: clone3(statement), jws, at: nowIso() };
      a.revealOpenedAt ??= nowIso();
      save(a);
      return { revealed: Object.keys(a.reveals).length, of: Object.keys(a.commits).length };
    },
    /**
     * Seals the credential. The template's minimum is enforced: every evidence item that needs human attestors (kind other than auto) must have at least
     * `attestors.min` revealed attestors, and a live-sitting template needs revealed marks on sitting evidence. `allowShortfall: true` is the operator's
     * explicit, recorded override (`process.shortfall`). Retrying after a crash is safe: log leaves are appended once and the credential id is derived.
     */
    finalize(assessmentId, { allowShortfall = false } = {}) {
      const a = getRec(assessmentId);
      if (a.state !== "open") throw err("state", "the assessment is already finalized", 409);
      const t = engine.getTemplate(a.templateId);
      const committed = Object.keys(a.commits).sort();
      const allRevealed = committed.every((k) => a.reveals[k]);
      if (!(a.invitations.length > 0 && allRevealed || nowMs() > Date.parse(a.revealBy))) throw err("not_ready", "commits are still waiting for their reveals and the reveal deadline has not passed", 409);
      const missing = committed.filter((k) => !a.reveals[k]);
      const notCommitted = a.invitations.map((i) => i.attestationId).filter((k) => !a.commits[k]).sort();
      const revealed = committed.filter((k) => a.reveals[k]);
      const shortfall = [];
      const byEv = new Map(a.evidence.map((e) => [e.id, /* @__PURE__ */ new Set()]));
      for (const k of revealed) byEv.get(a.reveals[k].statement.evidence)?.add(a.reveals[k].statement.attestor);
      for (const e of a.evidence) if (e.kind !== "auto" && byEv.get(e.id).size < t.attestors.min) shortfall.push(`${e.id}: ${byEv.get(e.id).size} revealed attestor(s), template minimum ${t.attestors.min}`);
      if (t.liveSitting && !a.evidence.some((e) => e.kind === "sitting" && byEv.get(e.id).size > 0)) shortfall.push("liveSitting: no sitting evidence has a revealed attestor");
      if (shortfall.length && !allowShortfall) throw err("below_template_minimum", "the template requirements are not met (" + shortfall.join("; ") + "); pass allowShortfall to finalize anyway, which is recorded in the credential", 409);
      const attestors = [...new Set(revealed.map((k) => a.reveals[k].statement.attestor))];
      const hist = finalizedStats();
      const stats = {};
      for (const d of attestors) stats[d] = has(hist, d) ? hist[d] : { sittings: 0, agreement: 0 };
      const bundle = sealBundle({
        skill: t.skill.id,
        claimedLevel: a.claimedLevel,
        subject: a.subject,
        evidence: a.evidence,
        attestations: revealed.map((k) => ({ statement: a.reveals[k].statement, signature: a.reveals[k].jws })),
        attestors: stats
      });
      const bundleHash = bundleHashOf(bundle);
      const logIdx = committed.map((k) => a.commits[k].logIndex);
      for (const k of missing) logIdx.push(log.appendOnce({ kind: "missing-reveal", ref: a.commits[k].commit }).index);
      for (const x of bundle.attestations) logIdx.push(log.appendOnce({ kind: "attestation", ref: x.hash }).index);
      logIdx.push(log.appendOnce({ kind: "bundle", ref: bundleHash }).index);
      const cp = log.checkpoint();
      const idx = [...new Set(logIdx)].sort((x, y) => x - y);
      const embedded = {
        logId,
        logKey: logSigner.did,
        entries: idx.map((i) => ({ index: i, leaf: log.entries(i, i + 1)[0].leaf })),
        proofs: idx.map((i) => ({ index: i, size: cp.payload.size, proof: log.inclusion(i, cp.payload.size).proof })),
        checkpoint: cp
      };
      const dids = [.../* @__PURE__ */ new Set([issuer.did, logSigner.did, ...attestors])].filter((d) => !d.startsWith(DID_KEY3)).map((d) => res.get(d)).filter(Boolean);
      const process2 = {
        invited: a.invitations.length,
        committed: committed.length,
        revealed: revealed.length,
        missing,
        late: [...a.late],
        notCommitted,
        ...(a.removed ?? []).length ? { removed: a.removed.map((r) => r.attestationId).sort() } : {},
        ...shortfall.length ? { shortfall } : {}
      };
      const doc = buildCredential({
        bundle,
        issuer,
        template: { id: t.id, hash: a.templateHash },
        assessment: a.id,
        process: process2,
        policy: t.policy,
        log: embedded,
        dids,
        now: nowMs(),
        id: uuidFrom(a.id + ":" + bundleHash)
      });
      store.put("credentials", doc.id, doc);
      a.state = "finalized";
      a.credentialId = doc.id;
      a.finalizedAt = nowIso();
      save(a);
      statsMemo = null;
      return clone3(doc);
    },
    getAssessment(id, { view = "public" } = {}) {
      const a = getRec(id);
      return view === "operator" ? clone3(a) : publicView(a);
    },
    getCredential(id) {
      const c = typeof id === "string" && ID_RE2.test(id) ? store.get("credentials", id) : null;
      if (!c) throw err("credential_unknown", "no such credential: " + id, 404);
      return c;
    },
    listAssessments() {
      return store.list("assessments").map((a) => ({ id: a.id, templateId: a.templateId, subject: a.subject, state: a.state, credentialId: a.credentialId ?? null, createdAt: a.createdAt }));
    },
    verifyCredential(doc, opts = {}) {
      let template = opts.template;
      if (template === void 0) {
        try {
          const tid = doc?.sanad?.template?.id;
          const rec = typeof tid === "string" && ID_RE2.test(tid) ? store.get("templates", tid) : null;
          if (rec && rec.hash === doc.sanad.template.hash) template = rec.template;
        } catch {
        }
      }
      return verifyCredential(doc, { ...opts, resolver: opts.resolver ?? res, trustedIssuers: opts.trustedIssuers ?? [issuer.did], trustedLogKeys: opts.trustedLogKeys ?? [logSigner.did], trustedLogIds: opts.trustedLogIds ?? [logId], ...template ? { template } : {} });
    },
    stats(did) {
      const all = finalizedStats(null);
      return did === void 0 ? all : typeof did === "string" && has(all, did) ? all[did] : { sittings: 0, agreement: 0 };
    },
    log,
    resolver: res,
    info() {
      return { engine: "0.2.0", alg: "sanad-0.1", issuer: issuer.did, logId, logKey: logSigner.did, time: nowIso(), today: today() };
    },
    /**
     * Read-only preview of recognition over the attestations revealed so far. It never reads an unrevealed mark (a commit holds no readable mark):
     * only the number of attestors still pending is returned. The result is always marked provisional and names whose policy produced it.
     */
    previewRecognition(assessmentId, { policy } = {}) {
      const a = getRec(assessmentId);
      const t = engine.getTemplate(a.templateId);
      if (policy !== void 0 && (policy === null || typeof policy !== "object" || Array.isArray(policy))) throw err("bad_policy", "policy must be an object");
      const base = policy ? { ...policy } : policyFromTemplate(t, today());
      delete base.id;
      const pol = { ...base, asOf: policy?.asOf ?? today() };
      const pp = validatePolicy(pol);
      if (pp.length) throw err("bad_policy", "policy refused: " + pp.join("; "));
      const revealed = Object.keys(a.reveals).sort();
      const hist = finalizedStats(), stats = {};
      for (const k of revealed) {
        const d = a.reveals[k].statement.attestor;
        stats[d] = has(hist, d) ? hist[d] : { sittings: 0, agreement: 0 };
      }
      const bundle = sealBundle({
        skill: t.skill.id,
        claimedLevel: a.claimedLevel,
        subject: a.subject,
        evidence: a.evidence,
        attestations: revealed.map((k) => ({ statement: a.reveals[k].statement, signature: a.reveals[k].jws })),
        attestors: stats
      });
      let recognition;
      try {
        recognition = recognise(bundle, pol);
      } catch (e) {
        throw err("bad_policy", "the recognition function refused the policy: " + (e?.message ?? e));
      }
      return {
        preview: true,
        provisional: true,
        state: a.state,
        policySource: policy ? "verifier-supplied" : "template-recommendation",
        counts: { invited: a.invitations.length, committed: Object.keys(a.commits).length, revealed: revealed.length, pending: Object.keys(a.commits).length - revealed.length, notCommitted: a.invitations.length - Object.keys(a.commits).length },
        recognition,
        note: "Computed only from revealed attestations; marks not yet revealed are not read. Not a credential: the final result can differ once the remaining attestors reveal or the deadline passes."
      };
    },
    /** What a host hands one attestor's client so it can sign the commit and the attestation (DESIGN section 8a). Contains no secret. */
    ticketFor(assessmentId, attestationId) {
      const a = getRec(assessmentId);
      const inv2 = a.invitations.find((i) => i.attestationId === attestationId);
      if (!inv2) throw err("not_invited", "no invitation " + attestationId, 404);
      const t = engine.getTemplate(a.templateId);
      const ev = a.evidence.find((e) => e.id === inv2.evidence);
      return clone3({
        ticketVersion: 1,
        alg: "sanad-0.1",
        assessment: a.id,
        attestationId,
        attestor: inv2.attestor,
        role: inv2.role,
        evidence: inv2.evidence,
        templateHash: a.templateHash,
        levels: t.levels.map((l) => l.level),
        ...t.levelMap ? { levelMap: t.levelMap } : {},
        commitBy: a.commitBy,
        revealBy: a.revealBy,
        state: a.state,
        revealOpen: revealOpen(a) || a.state === "finalized",
        serverTime: nowIso(),
        serverDay: today(),
        rules: {
          nonce: { pattern: NONCE_RE.source, minLength: 22, hint: "16 random bytes as base64url; optional native-mark form nm-<native>-<random> when the template has a levelMap" },
          date: { format: "YYYY-MM-DD", notBefore: ev.date, notAfter: "the host day at the moment of the reveal (use serverDay from the same provider)" },
          level: "integer listed in levels"
        },
        commit: { typ: "sanad-commit+jws", members: ["type", "assessment", "attestationId", "attestor", "evidence", "role", "commit", "templateHash"], type: "sanad-commit", commit: "sha256(canonical({attestor, evidence, level, nonce})) as 64 lowercase hex", post: `/v1/assessments/${a.id}/commit` },
        attestation: { typ: "sanad-attestation+jws", members: ["id", "attestor", "evidence", "level", "role", "conflictDeclared", "date", "commit", "nonce"], id: attestationId, post: `/v1/assessments/${a.id}/reveal` }
      });
    }
  };
  return engine;
}

// engine/src/demo-keys.mjs
var demo_keys_exports = {};
__export(demo_keys_exports, {
  createDemoAttestor: () => createDemoAttestor
});
var toSeed = (seed) => {
  if (seed instanceof Uint8Array) return seed;
  if (typeof seed === "string" && /^[0-9a-f]{64}$/.test(seed)) return new Uint8Array(Buffer.from(seed, "hex"));
  throw new Error("seed must be 32 bytes or 64 lowercase hex characters");
};
function createDemoAttestor(name, seed) {
  const kp = seed === void 0 ? generateKeyPair() : keyPairFromSeed(toSeed(seed));
  const signer = makeSigner(kp.privateKey);
  return { name, did: signer.did, kid: signer.kid, signer, privateKeyPkcs8: exportPrivateKey(kp.privateKey) };
}

// engine/src/http.mjs
import { createServer } from "node:http";
import { createHash as createHash4, timingSafeEqual } from "node:crypto";
import { readFileSync as readFileSync2 } from "node:fs";
import { dirname, join as join2 } from "node:path";
import { fileURLToPath } from "node:url";
var BODY_LIMIT = 256 * 1024;
var HERE = dirname(fileURLToPath(import.meta.url));
var STATIC_DIR = join2(HERE, "../static");
var FILES = { "/": ["index.html", "text/html; charset=utf-8"], "/app.js": ["app.js", "text/javascript; charset=utf-8"], "/sanad-client.js": ["sanad-client.js", "text/javascript; charset=utf-8"], "/style.css": ["style.css", "text/css; charset=utf-8"] };
var CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
var SECURITY = { "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store" };
var MAX_ENTRIES = 1e3;
var DRAIN_LIMIT = 1024 * 1024;
var err2 = (code, message, status = 400) => new EngineError(code, message, status);
var sha2 = (s) => createHash4("sha256").update(s).digest();
var isObj5 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function readBody(req) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (ct !== "application/json") return reject(err2("unsupported_media_type", "content-type must be application/json", 415));
    const chunks = [];
    let n = 0;
    let dead = false;
    req.on("data", (c) => {
      n += c.length;
      if (dead) {
        if (n > BODY_LIMIT + DRAIN_LIMIT) req.destroy();
        return;
      }
      if (n > BODY_LIMIT) {
        dead = true;
        reject(err2("body_too_large", "the body is larger than " + BODY_LIMIT + " bytes", 413));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (dead) return;
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
      } catch {
        return reject(err2("bad_json", "the body is not valid UTF-8"));
      }
      try {
        scanJsonText(text);
      } catch (e) {
        return reject(e);
      }
      let v;
      try {
        v = JSON.parse(text);
      } catch {
        return reject(err2("bad_json", "the body is not valid JSON"));
      }
      try {
        checkIJson(v);
      } catch (e) {
        return reject(e);
      }
      resolve(v);
    });
    req.on("error", () => {
      if (!dead) {
        dead = true;
        reject(err2("bad_request", "the request could not be read"));
      }
    });
  });
}
var intParam = (q, name, def) => {
  const v = q.get(name);
  if (v === null) return def;
  if (!/^\d{1,9}$/.test(v)) throw err2("bad_query", name + " must be a non-negative integer");
  return Number(v);
};
function createHttpServer({ engine, operatorToken, serveStatic = true, onError = (m) => process.stderr.write(m + "\n") } = {}) {
  if (!engine) throw err2("bad_config", "an engine is required");
  if (typeof operatorToken !== "string" || operatorToken.length < 16) throw err2("bad_config", "operatorToken must be a string of at least 16 characters");
  const tokenHash = sha2(operatorToken);
  const staticCache = /* @__PURE__ */ new Map();
  const staticFile = (name) => {
    if (!staticCache.has(name)) staticCache.set(name, readFileSync2(join2(STATIC_DIR, name)));
    return staticCache.get(name);
  };
  const operator = (req) => {
    const h = String(req.headers.authorization ?? "");
    const m = /^Bearer (.+)$/.exec(h);
    if (!m || !timingSafeEqual(sha2(m[1]), tokenHash)) throw err2("unauthorized", "a valid operator token is required", 401);
  };
  const routes = [];
  const route = (method, path, handler, op = false) => routes.push({ method, parts: path.split("/").slice(1), handler, op });
  route("GET", "/healthz", () => ({ ok: true }));
  route("GET", "/v1/info", () => engine.info());
  route("POST", "/v1/templates", ({ body }) => engine.registerTemplate(body), true);
  route("GET", "/v1/templates", () => engine.listTemplates());
  route("GET", "/v1/templates/:id", ({ p }) => engine.getTemplate(p.id));
  route("POST", "/v1/dids", ({ body }) => {
    if (isObj5(body) && "did" in body && "version" in body && "jws" in body) return engine.updateDid(body.did, body.version, body.jws);
    return engine.registerDid(body);
  }, true);
  route("GET", "/v1/dids/:did", ({ p }) => {
    const d = engine.resolver.get(p.did);
    if (!d) throw err2("did_unknown", "DID not registered: " + p.did, 404);
    return d;
  });
  route("POST", "/v1/assessments", ({ body }) => engine.createAssessment(body), true);
  route("GET", "/v1/assessments", () => engine.listAssessments(), true);
  route("GET", "/v1/assessments/:id", ({ p }) => engine.getAssessment(p.id));
  route("POST", "/v1/assessments/:id/invite", ({ p, body }) => engine.invite(p.id, body), true);
  route("GET", "/v1/assessments/:id/ticket/:att", ({ p }) => engine.ticketFor(p.id, p.att));
  route("POST", "/v1/assessments/:id/preview", ({ p, body }) => {
    if (!isObj5(body)) throw err2("bad_request", "the body must be an object, optionally { policy }");
    return engine.previewRecognition(p.id, { policy: body.policy });
  });
  route("POST", "/v1/assessments/:id/invitations/:att/remove", ({ p, body }) => engine.removeInvitation(p.id, p.att, { reason: isObj5(body) ? body.reason : void 0 }), true);
  route("POST", "/v1/assessments/:id/commit", ({ p, body }) => engine.commit(p.id, body));
  route("POST", "/v1/assessments/:id/reveal", ({ p, body }) => engine.reveal(p.id, body));
  route("POST", "/v1/assessments/:id/finalize", ({ p, body }) => engine.finalize(p.id, { allowShortfall: isObj5(body) && body.allowShortfall === true }), true);
  route("GET", "/v1/credentials/:id", ({ p }) => engine.getCredential(p.id));
  route("POST", "/v1/verify", ({ body }) => {
    if (!isObj5(body) || !("credential" in body)) throw err2("bad_request", "the body must be { credential, policy | useRecommendedPolicy, asOf?, trustedIssuers?, trustedLogKeys?, ... } (DESIGN section 8)");
    const c = body.credential, b = c?.sanad?.bundle, l = c?.sanad?.log;
    if (Array.isArray(b?.attestations) && b.attestations.length > VERIFY_LIMITS.attestations || Array.isArray(b?.evidence) && b.evidence.length > VERIFY_LIMITS.evidence || Array.isArray(l?.entries) && l.entries.length > VERIFY_LIMITS.logEntries || Array.isArray(c?.sanad?.dids) && c.sanad.dids.length > VERIFY_LIMITS.dids) throw err2("too_large", "the credential has more attestations, evidence items, log entries or DID histories than one verification call accepts");
    const opts = {};
    if (body.policy !== void 0) {
      if (!isObj5(body.policy)) throw err2("bad_request", "policy must be an object");
      opts.policy = body.policy;
    }
    for (const k of ["trustedIssuers", "trustedLogKeys", "trustedLogIds", "allowedAttestors"]) {
      if (body[k] === void 0) continue;
      if (!Array.isArray(body[k]) || !body[k].every((x) => typeof x === "string")) throw err2("bad_request", k + " must be a list of strings");
      opts[k] = body[k];
    }
    for (const k of ["useRecommendedPolicy", "useVerifierClock", "allowUnpinned", "allowIssuerStatistics", "allowEmbeddedDids"]) {
      if (body[k] === void 0) continue;
      if (typeof body[k] !== "boolean") throw err2("bad_request", k + " must be true or false");
      opts[k] = body[k];
    }
    for (const k of ["pinnedKeys", "attestorStats"]) {
      if (body[k] === void 0) continue;
      if (!isObj5(body[k])) throw err2("bad_request", k + " must be an object");
      opts[k] = body[k];
    }
    if (body.trustedDidHistories !== void 0) {
      if (!Array.isArray(body.trustedDidHistories)) throw err2("bad_request", "trustedDidHistories must be a list");
      opts.trustedDidHistories = body.trustedDidHistories;
    }
    if (body.asOf !== void 0) {
      if (typeof body.asOf !== "string") throw err2("bad_request", "asOf must be a string");
      opts.asOf = body.asOf;
    }
    return engine.verifyCredential(c, opts);
  });
  route("GET", "/v1/log/checkpoint", () => engine.log.checkpoint());
  route("GET", "/v1/log/entries", ({ q }) => {
    const size = engine.log.size();
    const from = intParam(q, "from", 0), to = Math.min(intParam(q, "to", size), size, from + MAX_ENTRIES);
    if (from > to) throw err2("bad_query", "from must not exceed to");
    return { size, from, to, entries: engine.log.entries(from, to) };
  });
  route("GET", "/v1/log/inclusion", ({ q }) => {
    const index = intParam(q, "index", null);
    if (index === null) throw err2("bad_query", "index is required");
    const size = intParam(q, "size", engine.log.size());
    if (size > engine.log.size() || index >= size) throw err2("bad_query", "index and size must lie inside the log");
    return engine.log.inclusion(index, size);
  });
  route("GET", "/v1/log/consistency", ({ q }) => {
    const m = intParam(q, "m", null);
    if (m === null) throw err2("bad_query", "m is required");
    const n = intParam(q, "n", engine.log.size());
    if (n > engine.log.size() || m > n) throw err2("bad_query", "m and n must satisfy m <= n <= log size");
    return engine.log.consistency(m, n);
  });
  route("GET", "/v1/attestors/:did/stats", ({ p }) => engine.stats(p.did));
  const match = (method, segs) => {
    let pathSeen = false;
    for (const r of routes) {
      if (r.parts.length !== segs.length) continue;
      const p = {};
      let ok = true;
      for (let i = 0; i < segs.length; i++) {
        if (r.parts[i].startsWith(":")) p[r.parts[i].slice(1)] = segs[i];
        else if (r.parts[i] !== segs[i]) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      pathSeen = true;
      if (r.method === method) return { r, p };
    }
    return pathSeen ? "method" : null;
  };
  const send = (res, status, body, headers = {}) => {
    const data = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    res.writeHead(status, { ...SECURITY, "content-length": Buffer.byteLength(data), ...headers });
    res.end(data);
  };
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const method = req.method ?? "GET";
      if (serveStatic && method === "GET" && FILES[url.pathname]) {
        const [name, type] = FILES[url.pathname];
        return send(res, 200, staticFile(name), { "content-type": type, "content-security-policy": CSP });
      }
      let segs;
      try {
        segs = url.pathname.split("/").slice(1).map((s) => decodeURIComponent(s));
      } catch {
        throw err2("bad_path", "the path is not valid");
      }
      const m = match(method, segs);
      if (m === null) throw err2("not_found", "no such route", 404);
      if (m === "method") throw err2("method_not_allowed", "method not allowed", 405);
      if (m.r.op) operator(req);
      const body = method === "POST" ? await readBody(req) : void 0;
      const out = await m.r.handler({ p: m.p, q: url.searchParams, body, req });
      return send(res, 200, out, { "content-type": "application/json; charset=utf-8" });
    } catch (e) {
      const known = e instanceof EngineError;
      const status = known ? e.status : 500;
      const payload = known ? { error: e.code, message: e.message } : { error: "internal", message: "internal error" };
      if (known && e.reason) payload.reason = e.reason;
      if (!known) {
        try {
          onError("sanad-engine internal error: " + (e?.name ?? "Error") + ": " + String(e?.message ?? e).slice(0, 200));
        } catch {
        }
      }
      if (status === 413) res.once("finish", () => req.destroy());
      if (!res.headersSent) send(res, status, payload, { "content-type": "application/json; charset=utf-8", ...status === 413 ? { connection: "close" } : {} });
      else res.end();
    }
  });
}
export {
  ATTESTATION_TYP,
  BODY_LIMIT,
  CREDENTIAL_TYP,
  CSP,
  DID_LIMITS,
  DID_UPDATE_TYP,
  EngineError,
  MAX_DEPTH,
  NONCE_RE,
  NOTICE,
  STATIC_DIR,
  VERIFY_LIMITS,
  assertTemplate,
  attestationStatement,
  attestorStats,
  b64u,
  base58btcDecode,
  base58btcEncode,
  buildCredential,
  bundleHashOf,
  checkCommit,
  checkIJson,
  checkReveal,
  commitFor,
  commitStatement,
  consistencyProof,
  core_exports as core,
  createEngine,
  createFileStore,
  createHttpServer,
  createLog,
  createMemoryStore,
  createResolver,
  createSqliteStore,
  demo_keys_exports as demo,
  didKeyFromPublicKey,
  exportPrivateKey,
  fail,
  fromB64u,
  generateKeyPair,
  importPrivateKey,
  inclusionProof,
  isIsoDate,
  isIsoTime,
  isSmallOrderKey,
  jwsHeader,
  keyPairFromSeed,
  kidForDidKey,
  leafBytes,
  leafHash,
  levelFromNative,
  makeSigner,
  merkleRoot,
  nativeOfNonce,
  newNonce,
  nodeHash,
  nonceWithNative,
  openStore,
  parseJws,
  policyFromTemplate,
  prepareCommit,
  prepareReveal,
  publicKeyFromDidKey,
  publicKeyOf,
  scanJsonText,
  sealBundle,
  signJws,
  sqliteAvailable,
  templateHash,
  validatePolicy,
  validateTemplate,
  verifyCheckpoint,
  verifyConsistency,
  verifyCredential,
  verifyInclusion,
  verifyJws
};
