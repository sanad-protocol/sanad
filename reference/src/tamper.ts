// Changes one field of a sealed credential WITHOUT re-sealing it: what a forger would do. Used by the tests and by the page's "tamper" switch.
import type { Credential } from './types';

export type TamperOp = { attestation: string; set: Record<string, unknown> } | { evidence: string; set: Record<string, unknown> };

function setPath(o: Record<string, unknown>, path: string, value: unknown) {
  const parts = path.split('.'); let cur = o;
  for (let i = 0; i < parts.length - 1; i++) cur = (cur[parts[i]] = { ...(cur[parts[i]] as Record<string, unknown>) }) as Record<string, unknown>;
  cur[parts[parts.length - 1]] = value;
}
export function applyTamper(c: Credential, ops: TamperOp[]): Credential {
  const out: Credential = JSON.parse(JSON.stringify(c));
  for (const op of ops) {
    const target = 'attestation' in op ? out.attestations.find((a) => a.id === op.attestation) : out.evidence.find((e) => e.id === op.evidence);
    if (!target) throw new Error('tamper target not found');
    for (const [k, v] of Object.entries(op.set)) setPath(target as unknown as Record<string, unknown>, k, v);
  }
  return out;
}
