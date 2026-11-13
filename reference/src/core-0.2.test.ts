// Core 0.2.0 additions: the optional signature check of R1, the widened exports, and the hand-kept type declarations.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as core from './index';
import { DEFAULT_POLICY } from './types';

describe('optional signature check (R1)', () => {
  it('without a check the result is exactly the v0.1 result', () => {
    const c = core.sampleCredential();
    expect(core.recognise(c, DEFAULT_POLICY, {})).toEqual(core.recognise(c, DEFAULT_POLICY));
  });
  it('a failing signature drops that attestation under R1, and the chain is unaffected for the others', () => {
    const c = core.sampleCredential();
    const r = core.recognise(c, DEFAULT_POLICY, { verifySignature: (a) => a.id !== 'att-02' });
    expect(r.dropped).toContainEqual({ id: 'att-02', rule: 'R1', reason: 'the signature does not verify' });
    expect(r.dropped.filter((d) => d.rule === 'R1').map((d) => d.id)).toEqual(['att-02']);
  });
  it('a check that throws counts as a failure', () => {
    const r = core.recognise(core.sampleCredential(), DEFAULT_POLICY, { verifySignature: () => { throw new Error('x'); } });
    expect(r.dropped.filter((d) => d.rule === 'R1')).toHaveLength(4);
  });
  it('only an exact true passes', () => {
    const r = core.recognise(core.sampleCredential(), DEFAULT_POLICY, { verifySignature: (() => 1) as unknown as () => boolean });
    expect(r.dropped.filter((d) => d.rule === 'R1')).toHaveLength(4);
  });
});

describe('exports and declarations', () => {
  it('the sealing helpers are exported and agree with sealCredential', () => {
    const c = core.sampleCredential();
    for (const a of c.attestations) { expect(core.commitOf(a)).toBe(a.commit); expect(core.attestationHashOf(a)).toBe(a.hash); }
    for (const e of c.evidence) expect(core.evidenceHash(e)).toBe(e.hash);
  });
  it('every runtime export is declared in the .d.ts file', () => {
    const dts = readFileSync(new URL('../types/sanad-reference.d.ts', import.meta.url), 'utf8');
    for (const name of Object.keys(core)) expect(dts, name).toMatch(new RegExp(`declare (const|function) ${name}\\b`));
  });
});
