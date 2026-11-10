// Attestor statistics derived from finalized assessments (DESIGN.md section 7).

const lowerMedian = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor((s.length - 1) / 2)]; };

/**
 * @param {{ evidence: { id: string, kind: string }[], marks: { attestor: string, evidence: string, level: number }[] }[]} records one per finalized assessment
 * @returns {Record<string, { sittings: number, agreement: number }>} keys sorted
 */
export function attestorStats(records) {
  const acc = new Map();
  const get = (did) => { let a = acc.get(did); if (!a) acc.set(did, a = { sittings: 0, agree: 0, total: 0 }); return a; };
  for (const rec of records) {
    const kinds = new Map(rec.evidence.map((e) => [e.id, e.kind]));
    const byItem = new Map();
    for (const m of rec.marks) { if (!byItem.has(m.evidence)) byItem.set(m.evidence, []); byItem.get(m.evidence).push(m); }
    const sat = new Set();
    for (const [item, marks] of byItem) {
      for (const m of marks) {
        const a = get(m.attestor);
        if (kinds.get(item) === 'sitting') sat.add(m.attestor);
        const others = marks.filter((o) => o.attestor !== m.attestor).map((o) => o.level);
        if (others.length === 0) continue;
        a.total++;
        if (Math.abs(m.level - lowerMedian(others)) <= 1) a.agree++;
      }
    }
    for (const did of sat) get(did).sittings++;
  }
  const out = {};
  for (const did of [...acc.keys()].sort()) {
    const a = acc.get(did);
    // defineProperty, so that a key such as "__proto__" becomes a data member and never changes the prototype
    Object.defineProperty(out, did, { enumerable: true, configurable: true, writable: true, value: { sittings: a.sittings, agreement: a.total === 0 ? 0 : Math.round((a.agree / a.total) * 1000) / 1000 } });
  }
  return out;
}
