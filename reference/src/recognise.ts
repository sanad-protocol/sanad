// The Sanad v0.1 recognition function: (credential, verifier policy) -> level, confidence, status and a step-by-step explanation.
// Pure and deterministic: no clock, no randomness, no network; inputs are sorted by id first. Anyone can recompute it from the published data.
// Rules (stable ids): R1 integrity, R2 admissibility, R3 age factor, R4 per-evidence level, R5 independence, R6 recognised level, R7 confidence. R8 (inference) is in infer.ts.
import { hashOf } from './canon';
import { attestationHashOf, commitOf } from './seal';
import {
  SANAD_VERSION, type Attestation, type Credential, type Dropped, type Evidence, type EvidenceKind, type Level, type Policy, type Recognition, type Status, type Step,
} from './types';

export const WEIGHT: Record<EvidenceKind, number> = { auto: 0.25, sitting: 0.6, artifact: 0.3, peer: 0.15 };
export const CAP: Record<EvidenceKind, Level> = { auto: 3, sitting: 5, artifact: 4, peer: 3 };
/** Kinds whose evidence needs independent human attestors and can lead to the status "recognised". */
export const QUALIFYING: readonly EvidenceKind[] = ['sitting', 'artifact'];
export const REPLAY = 'replay';
const MONTH_DAYS = 30.4375;
const KINDS: readonly EvidenceKind[] = ['auto', 'sitting', 'artifact', 'peer'];

const byId = <T extends { id: string }>(a: T, b: T) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const round3 = (x: number) => Math.round(x * 1000) / 1000;
const lowerMedian = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor((s.length - 1) / 2)]; };
const uniq = <T,>(xs: T[]) => [...new Set(xs)];
const f2 = (x: number) => (Math.round(x * 100) / 100).toString();

/** Days since 1970-01-01 for an ISO yyyy-mm-dd date, or NaN when it is not one. */
export function dayNumber(iso: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso); if (!m) return NaN;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3]); const d = new Date(t);
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? t / 86400000 : NaN;
}
const levelOk = (v: unknown): v is Level => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 5;

export interface Integrity { id: string; ok: boolean; reason: string }
/** Options of R1. `verifySignature` (optional): returns true when the attestation's signature verifies. Without it signatures are not checked (v0.1 behaviour). */
export interface RecogniseOptions { verifySignature?: (a: Attestation) => boolean }
/** R1 as a function of its own (the page's verify panel shows it): every evidence hash, every attestation hash, reveal-against-commit and chain link, and the signature when a check is given. */
export function checkIntegrity(cred: Credential, opts: RecogniseOptions = {}): { evidence: Integrity[]; attestations: Integrity[] } {
  const evs = [...cred.evidence].sort(byId), atts = [...cred.attestations].sort(byId);
  const evidence = evs.map((e): Integrity => {
    const why: string[] = [];
    if (!KINDS.includes(e.kind)) why.push('unknown kind "' + e.kind + '"');
    if (Number.isNaN(dayNumber(e.date))) why.push('date is not a valid yyyy-mm-dd');
    let h = ''; try { h = hashOf(e.body); } catch { why.push('body cannot be canonicalised'); }
    if (h && h !== e.hash) why.push('its content no longer matches its hash (changed after sealing)');
    if (e.kind === 'auto' && !levelOk(e.body?.autoLevel)) why.push('an automatic record needs autoLevel 0..5 in its body');
    return { id: e.id, ok: why.length === 0, reason: why.join('; ') };
  });
  const evOk = new Map(evidence.map((x) => [x.id, x.ok]));
  const attestations = atts.map((a, i): Integrity => {
    const why: string[] = [];
    if (!levelOk(a.level)) why.push('level is not 0..5');
    else {
      if (attestationHashOf(a) !== a.hash) why.push('its content no longer matches its hash (changed after sealing)');
      if (commitOf(a) !== a.commit) why.push('the revealed mark does not match the commitment made before marking');
    }
    if (opts.verifySignature) { let good = false; try { good = opts.verifySignature(a) === true; } catch { good = false; } if (!good) why.push('the signature does not verify'); }
    const expectPrev = i === 0 ? 'GENESIS' : atts[i - 1].hash;
    if (a.prev !== expectPrev) why.push('chain break: it does not link to the attestation before it');
    if (!evOk.has(a.evidence)) why.push('it attests evidence "' + a.evidence + '" that is not in the credential');
    else if (!evOk.get(a.evidence)) why.push('it attests evidence "' + a.evidence + '" that failed integrity');
    if (Number.isNaN(dayNumber(a.date))) why.push('date is not a valid yyyy-mm-dd');
    return { id: a.id, ok: why.length === 0, reason: why.join('; ') };
  });
  return { evidence, attestations };
}

interface Item { att: Attestation | null; attestor: string; level: Level; evidence: Evidence }

export function recognise(cred: Credential, policy: Policy, opts: RecogniseOptions = {}): Recognition {
  if (!(policy.halfLifeMonths > 0) || !Number.isFinite(policy.halfLifeMonths)) throw new RangeError('halfLifeMonths must be a positive number');
  const asOf = dayNumber(policy.asOf); if (Number.isNaN(asOf)) throw new RangeError('asOf must be an ISO date yyyy-mm-dd');
  const minAtt = Math.max(1, Math.floor(policy.minAttestors));
  const steps: Step[] = []; const dropped: Dropped[] = [];
  const evs = [...cred.evidence].sort(byId), atts = [...cred.attestations].sort(byId);

  // ---- R1 integrity
  const integ = checkIntegrity(cred, opts);
  const evBad = new Map(integ.evidence.filter((x) => !x.ok).map((x) => [x.id, x.reason]));
  const attBad = new Map(integ.attestations.filter((x) => !x.ok).map((x) => [x.id, x.reason]));
  steps.push({ rule: 'R1', summary: `Checked ${evs.length} evidence item(s) and ${atts.length} attestation(s): every hash, every reveal against its commitment, and the chain. ${evBad.size + attBad.size} failed.`, inputs: [...evs.map((e) => e.id), ...atts.map((a) => a.id)], effect: evBad.size + attBad.size ? 'failed items are ignored' : 'nothing ignored' });
  for (const e of evs) if (evBad.has(e.id)) { dropped.push({ id: e.id, rule: 'R1', reason: evBad.get(e.id)! }); steps.push({ rule: 'R1', summary: `Evidence ${e.id} was ignored: ${evBad.get(e.id)}.`, inputs: [e.id], effect: 'dropped' }); }
  for (const a of atts) if (attBad.has(a.id)) { dropped.push({ id: a.id, rule: 'R1', reason: attBad.get(a.id)! }); steps.push({ rule: 'R1', summary: `Attestation ${a.id} (by ${a.attestor}) was ignored: ${attBad.get(a.id)}.`, inputs: [a.id, a.attestor], effect: 'dropped' }); }

  // ---- R2 admissibility
  const age = new Map<string, number>(); // months
  const evAdm = new Map<string, Evidence>();
  for (const e of evs) {
    if (evBad.has(e.id)) continue;
    const m = (asOf - dayNumber(e.date)) / MONTH_DAYS; age.set(e.id, m);
    if (m < 0) { dropped.push({ id: e.id, rule: 'R2', reason: 'dated after the evaluation day' }); steps.push({ rule: 'R2', summary: `Evidence ${e.id} was ignored: it is dated after the evaluation day ${policy.asOf}.`, inputs: [e.id], effect: 'dropped' }); continue; }
    if (m > 4 * policy.halfLifeMonths) { dropped.push({ id: e.id, rule: 'R2', reason: `older than 4 half-lives (${f2(m)} months; half-life ${policy.halfLifeMonths})` }); steps.push({ rule: 'R2', summary: `Evidence ${e.id} was ignored: ${f2(m)} months old, more than 4 half-lives (${policy.halfLifeMonths} months each).`, inputs: [e.id], effect: 'dropped' }); continue; }
    evAdm.set(e.id, e);
  }
  const items: Item[] = [];
  for (const e of evAdm.values()) if (e.kind === 'auto') items.push({ att: null, attestor: REPLAY, level: e.body.autoLevel as Level, evidence: e });
  for (const a of atts) {
    if (attBad.has(a.id)) continue; const e = evAdm.get(a.evidence); if (!e) continue; // its evidence was dropped (reported on the evidence)
    if (e.kind === 'auto') continue; // an automatic record carries its own replayed level
    const st = cred.attestors[a.attestor] ?? { sittings: 0, agreement: 0 };
    let why = '';
    if (a.conflictDeclared) why = 'a conflict of interest was declared';
    else if (st.sittings < policy.minAttestorSittings) why = `only ${st.sittings} sitting(s), policy needs ${policy.minAttestorSittings}`;
    else if (st.agreement < policy.minAgreement) why = `agreement with other examiners is ${f2(st.agreement)}, policy needs ${f2(policy.minAgreement)}`;
    if (why) { dropped.push({ id: a.id, rule: 'R2', reason: why }); steps.push({ rule: 'R2', summary: `Attestor ${a.attestor} (attestation ${a.id}) was ignored: ${why}.`, inputs: [a.id, a.attestor], effect: 'dropped' }); continue; }
    items.push({ att: a, attestor: a.attestor, level: a.level, evidence: e });
  }
  steps.push({ rule: 'R2', summary: `${items.length} attestation(s) and automatic record(s) are admissible on ${new Set(items.map((i) => i.evidence.id)).size} evidence item(s).`, inputs: items.map((i) => i.att?.id ?? i.evidence.id), effect: 'these are used' });

  // ---- R3 age factor, R4 per-evidence level
  const factor = new Map<string, number>(); const evLevel = new Map<string, Level>(); const evSpread = new Map<string, number>();
  const evItems = new Map<string, Item[]>(); for (const it of items) { const l = evItems.get(it.evidence.id) ?? []; l.push(it); evItems.set(it.evidence.id, l); }
  for (const e of evs) {
    const its = evItems.get(e.id); if (!its) continue;
    const m = age.get(e.id)!; const a = Math.pow(0.5, m / policy.halfLifeMonths); factor.set(e.id, a);
    steps.push({ rule: 'R3', summary: `Evidence ${e.id} is ${f2(m)} month(s) old: age factor ${a.toFixed(3)} (half-life ${policy.halfLifeMonths} months).`, inputs: [e.id], effect: `weight x ${a.toFixed(3)}` });
    const lv = its.map((i) => i.level); const med = lowerMedian(lv); const cap = CAP[e.kind]; const lvl = Math.min(med, cap) as Level;
    evLevel.set(e.id, lvl); evSpread.set(e.id, Math.max(...lv) - Math.min(...lv));
    steps.push({ rule: 'R4', summary: `Evidence ${e.id} (${e.kind}): levels ${JSON.stringify([...lv].sort((x, y) => x - y))}, lower median ${med}${med > cap ? `, capped at ${cap} for ${e.kind} evidence` : ''} -> level ${lvl}.`, inputs: [e.id, ...its.map((i) => i.att?.id ?? e.id)], effect: `evidence level ${lvl}` });
  }
  for (const e of evAdm.values()) if (!evItems.has(e.id)) steps.push({ rule: 'R4', summary: `Evidence ${e.id} has no admissible attestation, so it does not count.`, inputs: [e.id], effect: 'no level' });

  // ---- R5 independence
  const qual = [...evLevel.keys()].filter((id) => QUALIFYING.includes(evAdm.get(id)!.kind));
  const attestors = uniq(qual.flatMap((id) => evItems.get(id)!.map((i) => i.attestor))).sort();
  const live = qual.some((id) => evAdm.get(id)!.kind === 'sitting');
  const reasons: string[] = [];
  if (!qual.length) reasons.push('there is no live-sitting or artifact evidence with an admissible attestor');
  if (attestors.length < minAtt) reasons.push(`${attestors.length} independent attestor(s) count, policy needs ${minAtt}`);
  if (policy.requireLive && !live) reasons.push('policy requires a live sitting and none is admissible');
  const independent = reasons.length === 0;
  const hasEvidence = evLevel.size > 0;
  steps.push({ rule: 'R5', summary: independent ? `${attestors.length} distinct admissible attestor(s) (${attestors.join(', ')}); policy needs ${minAtt}${policy.requireLive ? ' and a live sitting, which is present' : ''}. Independence is met.` : `Independence is not met: ${reasons.join('; ')}.`, inputs: attestors, effect: independent ? 'status can be recognised' : 'status is provisional' });

  // ---- R6 recognised level
  const attestedLevel: Level | null = qual.length ? (Math.min(cred.claimedLevel, lowerMedian(qual.map((id) => evLevel.get(id)!))) as Level) : null;
  const weak = [...evLevel.keys()].filter((id) => !QUALIFYING.includes(evAdm.get(id)!.kind)).map((id) => evLevel.get(id)!);
  let status: Status; let level: Level;
  if (!hasEvidence) { status = 'not-recognised'; level = 0; }
  else if (independent) { status = 'recognised'; level = attestedLevel!; }
  else { status = 'provisional'; level = Math.min(cred.claimedLevel, weak.length ? Math.max(...weak) : 0) as Level; }
  steps.push({ rule: 'R6', summary: !hasEvidence ? 'There is no admissible evidence: nothing is recognised.' : independent ? `Recognised level = the lower of the claim (${cred.claimedLevel}) and the lower median of the live-sitting and artifact evidence levels (${JSON.stringify(qual.map((id) => evLevel.get(id)!).sort((x, y) => x - y))}) = ${level}.` : `Provisional: the level is limited to the best automatic or peer evidence (${weak.length ? Math.max(...weak) : 'none'}), so it is ${level}.${attestedLevel !== null ? ` If the policy were met it would be ${attestedLevel}.` : ''}`, inputs: qual, effect: `level ${level}, ${status}` });

  // ---- R7 confidence
  let miss = 1;
  for (const it of items) { const e = it.evidence; const f = (evSpread.get(e.id) ?? 0) <= 1 ? 1 : 0.5; miss *= 1 - WEIGHT[e.kind] * factor.get(e.id)! * f; }
  const confidence = hasEvidence ? round3(1 - miss) : 0;
  const halved = [...evSpread.entries()].filter(([, s]) => s > 1).map(([id]) => id);
  steps.push({ rule: 'R7', summary: hasEvidence ? `Confidence = 1 - the product of (1 - weight x age factor x agreement factor) over ${items.length} item(s) = ${confidence.toFixed(3)}.${halved.length ? ` Attestors of ${halved.join(', ')} disagree by more than one level, so their weight was halved.` : ''}` : 'No admissible evidence: confidence 0.', inputs: items.map((i) => i.att?.id ?? i.evidence.id), effect: `confidence ${confidence.toFixed(3)}` });

  return {
    version: SANAD_VERSION, skill: cred.skill, claimedLevel: cred.claimedLevel, status, level, attestedLevel, confidence, explanation: steps, dropped,
    used: { evidence: [...evLevel.keys()].sort(), attestations: items.filter((i) => i.att).map((i) => i.att!.id).sort() }, policy,
  };
}
