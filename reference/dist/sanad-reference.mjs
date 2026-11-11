// Sanad core 0.2.0, algorithm sanad-0.1 (Apache-2.0). Generated from reference/src by reference/build.mjs.

// reference/src/types.ts
var SANAD_VERSION = "sanad-0.1";
var DEFAULT_POLICY = { minAttestors: 2, requireLive: true, halfLifeMonths: 24, minAttestorSittings: 3, minAgreement: 0.6, maxInferenceDepth: 2, inferenceDecay: 0.7, asOf: "2026-11-07" };

// reference/src/sha256.ts
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

// reference/src/canon.ts
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

// reference/src/seal.ts
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

// reference/src/tamper.ts
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

// reference/src/recognise.ts
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
    if (a.attestor === REPLAY) why.push('the attestor name "' + REPLAY + '" is reserved for automatic records and cannot be a human attestor');
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
  if (!levelOk(cred.claimedLevel)) throw new RangeError("claimedLevel must be an integer from 0 to 5");
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
    const raw = Object.prototype.hasOwnProperty.call(cred.attestors, a.attestor) ? cred.attestors[a.attestor] : void 0;
    const st = raw && Number.isFinite(raw.sittings) && Number.isFinite(raw.agreement) ? raw : { sittings: 0, agreement: 0 };
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

// reference/src/infer.ts
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

// reference/src/sample.ts
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
export {
  CAP,
  DEFAULT_POLICY,
  QUALIFYING,
  REPLAY,
  SAMPLE_NAMES,
  SAMPLE_SKILL,
  SAMPLE_TAMPER,
  SANAD_VERSION,
  WEIGHT,
  applyTamper,
  assertPolicy,
  attestationHashOf,
  attestationPayload,
  canonical,
  checkIntegrity,
  commitOf,
  commitPayload,
  dayNumber,
  evidenceHash,
  explainInference,
  graphFromEdges,
  hashOf,
  infer,
  policyProblems,
  recognise,
  sampleCredential,
  sealAttestations,
  sealCredential,
  sealEvidence,
  sha256Hex,
  sha256HexWebCrypto
};
