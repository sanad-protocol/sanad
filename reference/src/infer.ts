// Sanad v0.1 rule R8: hidden-skill inference over the prerequisite graph. A recognised skill at level L implies its prerequisites, one step further back each time,
// with a lower level and a decayed confidence. Everything inferred is flagged `inferred`, carries its derivation path, and is never published without the holder's choice.
import type { Inferred, Level, Policy, Step } from './types';

export interface SkillGraph { requires(id: string): readonly string[] }

/** Builds a graph from the topic map's data: ids and flat [prerequisite, dependent] edge pairs (site/public/graph3d.json). */
export function graphFromEdges(ids: readonly string[], edges: readonly number[]): SkillGraph {
  const req = new Map<string, string[]>(); for (let i = 0; i < edges.length; i += 2) { const to = ids[edges[i + 1]], from = ids[edges[i]]; const l = req.get(to) ?? []; l.push(from); req.set(to, l); }
  for (const l of req.values()) l.sort();
  return { requires: (id) => req.get(id) ?? [] };
}

const round3 = (x: number) => Math.round(x * 1000) / 1000;

export function infer(graph: SkillGraph, skill: string, level: Level, confidence: number, policy: Pick<Policy, 'maxInferenceDepth' | 'inferenceDecay'>, directClaims: Iterable<string> = []): Inferred[] {
  const direct = new Set(directClaims); direct.add(skill);
  const out: Inferred[] = []; const seen = new Set<string>([skill]);
  let layer: { id: string; path: string[] }[] = [{ id: skill, path: [skill] }];
  for (let d = 1; d <= policy.maxInferenceDepth && layer.length; d++) {
    const next: { id: string; path: string[] }[] = [];
    for (const n of layer) for (const p of [...graph.requires(n.id)].sort()) {
      if (seen.has(p)) continue; seen.add(p); const path = [...n.path, p]; next.push({ id: p, path });
      const lv = Math.max(0, level - d) as Level;
      if (!direct.has(p) && lv > 0) out.push({ skill: p, level: lv, confidence: round3(confidence * Math.pow(policy.inferenceDecay, d)), distance: d, path, inferred: true });
    }
    layer = next.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }
  return out.sort((a, b) => a.distance - b.distance || (a.skill < b.skill ? -1 : a.skill > b.skill ? 1 : 0));
}

export function explainInference(skill: string, inferred: Inferred[], policy: Pick<Policy, 'maxInferenceDepth' | 'inferenceDecay'>): Step {
  return { rule: 'R8', summary: `${inferred.length} prerequisite skill(s) up to ${policy.maxInferenceDepth} step(s) back are INFERRED from ${skill}: level drops by 1 per step, confidence is multiplied by ${policy.inferenceDecay} per step. They are suggestions for the holder, never claims.`, inputs: inferred.map((i) => i.skill), effect: 'flagged inferred; private until the holder publishes' };
}
