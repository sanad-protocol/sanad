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
  it('declares what it exports in index.d.ts', async () => {
    const d = readFileSync(fileURLToPath(new URL('../index.d.ts', import.meta.url)), 'utf8');
    const lib = await import('../src/index.mjs');
    const declared = new Set([...d.matchAll(/export (?:declare )?(?:function|const|class) (\w+)/g)].map((m) => m[1]));
    for (const n of declared) expect(n in lib, n).toBe(true);
    for (const n of ['createEngine', 'createHttpServer', 'verifyCredential', 'prepareCommit', 'prepareReveal', 'EngineError']) expect(declared.has(n), n).toBe(true);
  });
});
