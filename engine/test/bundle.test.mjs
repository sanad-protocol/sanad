import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { bundleText, OUT } from '../build.mjs';

describe('single-file bundle', () => {
  it('the committed bundle equals a fresh build and its recorded SHA-256 matches', async () => {
    const committed = readFileSync(OUT, 'utf8');
    expect(await bundleText()).toBe(committed);
    const rec = readFileSync(OUT + '.sha256', 'utf8').trim().split(/\s+/)[0];
    expect(createHash('sha256').update(committed).digest('hex')).toBe(rec);
  });
  it('has no imports other than node: built-ins', () => {
    const text = readFileSync(OUT, 'utf8');
    const imports = [...text.matchAll(/^\s*import\s[^;]*?from\s*["']([^"']+)["']/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const i of imports) expect(i).toMatch(/^node:/);
    expect(text).not.toMatch(/require\(/);
  });
  it('exports the same names as the library entry', async () => {
    const lib = await import('../src/index.mjs');
    const bundle = await import(pathToFileURL(OUT).href);
    expect(Object.keys(bundle).sort()).toEqual(Object.keys(lib).sort());
  });
  it('index.d.ts declares every runtime export, and nothing that does not exist', async () => {
    const d = readFileSync(fileURLToPath(new URL('../index.d.ts', import.meta.url)), 'utf8');
    const lib = await import('../src/index.mjs');
    const declared = new Set([...d.matchAll(/export (?:declare )?(?:async )?(?:function|const|class) (\w+)/g)].map((m) => m[1]));
    const undeclared = Object.keys(lib).filter((n) => !declared.has(n));
    expect(undeclared, 'exports missing from index.d.ts').toEqual([]);
    const ghosts = [...declared].filter((n) => !(n in lib));
    expect(ghosts, 'declared but not exported').toEqual([]);
  });
  it('declares the engine methods and verify options that exist', async () => {
    const d = readFileSync(fileURLToPath(new URL('../index.d.ts', import.meta.url)), 'utf8');
    const { createEngine, createMemoryStore, makeSigner, keyPairFromSeed } = await import('../src/index.mjs');
    const e = createEngine({ store: createMemoryStore(), issuer: makeSigner(keyPairFromSeed(new Uint8Array(32).fill(1)).privateKey), logSigner: makeSigner(keyPairFromSeed(new Uint8Array(32).fill(2)).privateKey) });
    const iface = d.slice(d.indexOf('export interface Engine {'), d.indexOf('export function createEngine'));
    for (const k of Object.keys(e)) expect(iface, 'Engine.' + k).toMatch(new RegExp('\\b' + k + '[(:]'));
    for (const o of ['policy', 'useRecommendedPolicy', 'asOf', 'useVerifierClock', 'trustedIssuers', 'trustedLogKeys', 'trustedLogIds', 'pinnedKeys', 'trustedDidHistories', 'allowUnpinned', 'allowEmbeddedDids', 'attestorStats', 'allowIssuerStatistics', 'allowedAttestors', 'template']) expect(d, o).toMatch(new RegExp('\\b' + o + '\\??:'));
    expect(d).not.toMatch(/Partial</);
  });
});
