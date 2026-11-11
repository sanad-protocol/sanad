import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { runVector } from '../vectors/harness.mjs';

const dir = fileURLToPath(new URL('../vectors/', import.meta.url));
const files = readdirSync(dir).filter((f) => /^engine-.*\.json$/.test(f)).sort();

describe('engine vectors (section 13)', () => {
  it('the vector files of the design (six of section 13 and three added later) exist', () => {
    expect(files).toEqual(['engine-clock-regression.json', 'engine-commit-reveal.json', 'engine-duplicate-attestor.json', 'engine-invitation-removed.json', 'engine-key-rotation.json', 'engine-late-reveal.json', 'engine-missing-reveal.json', 'engine-native-level-map.json', 'engine-preview-ticket.json', 'engine-tamper.json']);
  });
  for (const f of files) {
    it(f + ': every step matches its recorded expectation', () => {
      const v = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      const res = runVector(v);
      for (const r of res) { expect(v.steps[r.i].expect, 'step ' + r.i + ' has an expectation').toBeDefined(); expect(r.observed, 'step ' + r.i + ' ' + r.op).toEqual(v.steps[r.i].expect); }
    });
    it(f + ': is deterministic (a second run gives identical results)', () => {
      const v = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      expect(runVector(v).map((r) => r.observed)).toEqual(runVector(v).map((r) => r.observed));
    });
  }
  it('a changed expectation is detected (the harness is not vacuous)', () => {
    const v = JSON.parse(readFileSync(join(dir, 'engine-commit-reveal.json'), 'utf8'));
    v.steps.find((s) => s.op === 'finalize').expect.process.revealed = 1;
    expect(runVector(v).some((r) => !r.ok)).toBe(true);
  });
});
