// Runs the conformance vectors against the reference implementation and returns one result per vector (used by verify.mjs and by the site build).
export function runVectors(lib, data) {
  const { recognise, sealCredential, applyTamper, infer, SANAD_VERSION } = lib;
  const build = (v) => { const c = sealCredential(v.credential); return v.tamper ? applyTamper(c, v.tamper) : c; };
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const out = [];
  for (const v of data.vectors) {
    try {
      const r = recognise(build(v), v.policy); const e = v.expect; const problems = [];
      if (r.version !== SANAD_VERSION) problems.push('version ' + r.version);
      if (r.status !== e.status) problems.push(`status ${r.status} (expected ${e.status})`);
      if (r.level !== e.level) problems.push(`level ${r.level} (expected ${e.level})`);
      if (r.attestedLevel !== e.attestedLevel) problems.push(`attestedLevel ${r.attestedLevel} (expected ${e.attestedLevel})`);
      if (Math.abs(r.confidence - e.confidence) > 0.0005) problems.push(`confidence ${r.confidence} (expected ${e.confidence})`);
      if (!same(r.dropped.map((d) => [d.id, d.rule]).sort(), [...e.dropped].sort())) problems.push('dropped items differ');
      const seen = new Set(r.explanation.map((s) => s.rule)); for (const rule of e.rules) if (!seen.has(rule)) problems.push(`rule ${rule} missing from the explanation`);
      out.push({ kind: 'recognition', id: v.id, name: v.name, ok: problems.length === 0, status: r.status, level: r.level, confidence: r.confidence, rules: r.explanation.map((s) => s.rule), problems });
    } catch (err) { out.push({ kind: 'recognition', id: v.id, name: v.name, ok: false, problems: [String(err.message ?? err)] }); }
  }
  for (const t of data.inference ?? []) {
    try {
      const g = { requires: (id) => t.graph.requires[id] ?? [] }; const res = infer(g, t.skill, t.level, t.confidence, t.policy, t.direct);
      const got = res.map((o) => [o.skill, o.level, o.confidence, o.distance, o.path]);
      out.push({ kind: 'inference', id: t.id, name: t.name, ok: same(got, t.expect) && res.every((o) => o.inferred === true), summary: got.map((x) => `${x[0]}@${x[1]}`).join(' ') || '(none)', problems: [] });
    } catch (err) { out.push({ kind: 'inference', id: t.id, name: t.name, ok: false, problems: [String(err.message ?? err)] }); }
  }
  return out;
}
