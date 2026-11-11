import { describe, it, expect } from 'vitest';
import { runExample, SCENARIOS } from '../examples/run.mjs';

describe('examples', () => {
  for (const name of Object.keys(SCENARIOS)) {
    it(name + ': the scripted run seals a credential that verifies, and verifiers with different policies get different answers from one chain', () => {
      const r = runExample(name);
      expect(r.report.ok, JSON.stringify(r.report.checks.filter((c) => !c.ok))).toBe(true);
      expect(r.report.recognition.status).toBe('recognised');
      expect(r.strictReport.ok).toBe(true); // same chain, all checks still pass
      expect(r.strictReport.recognition.status).not.toBe('recognised'); // a stricter verifier recognises less
      expect(r.credential.sanad.policy.id).toBe(r.template.policy.id); // the template policy travels as a recommendation
    });
  }
});
