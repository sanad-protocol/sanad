import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { deflateRawSync, crc32 } from 'node:zlib';
import { buildHtml } from '../verifiers/browser/build.mjs';
import { readTree, verifyBundleFiles } from '../src/index.mjs';

const here = fileURLToPath(new URL('../verifiers/', import.meta.url));
const html = buildHtml();
// the page's scripts, run without a DOM: the same text a browser would run
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1].replace(/<\\\/script/g, '</script'));
const g = {};
new Function('globalThis', 'crypto', 'document', scripts.slice(0, 2).join('\n') + '\n' + scripts[2])(g, webcrypto, undefined);
const V = g.SanadVerifier;
const fixtures = readdirSync(join(here, 'fixtures')).filter((n) => !n.startsWith('_') && existsSync(join(here, 'fixtures', n, 'expected.json'))).sort();
const load = (name) => {
  const dir = join(here, 'fixtures', name);
  const c = JSON.parse(readFileSync(join(dir, 'case.json'), 'utf8'));
  return { files: readTree(join(dir, 'tree')), options: { ...c.options, now: Date.parse(c.evaluatedAt) }, expected: JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8')) };
};

describe('the single-file browser verifier', () => {
  it('is one self-contained file with no external reference and a restrictive CSP', () => {
    expect(html).not.toMatch(/<script[^>]+src=|<link[^>]+href=|@import|fetch\(|XMLHttpRequest|WebSocket|import\(/);
    expect(html).toMatch(/default-src 'none'/);
    expect(html.length).toBeLessThan(150000);
  });
  it('covers the fixtures at least as many cases as exist', () => { expect(fixtures.length).toBeGreaterThanOrEqual(10); });
  for (const name of fixtures) {
    it('fixture ' + name + ': same verdict, failed checks and recognition as the engine', async () => {
      const { files, options, expected } = load(name);
      const r = await V.verifyTree(files, options);
      expect(r.ok).toBe(expected.ok);
      expect(r.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(expected.checks.filter((c) => !c.ok).map((c) => c.name));
      expect(r.checks.map((c) => c.name)).toEqual(expected.checks.map((c) => c.name));
      expect(r.warnings.length).toBe(expected.warnings);
      if (expected.recognition) {
        expect(r.recognition).toMatchObject({ status: expected.recognition.status, level: expected.recognition.level, attestedLevel: expected.recognition.attestedLevel, confidence: expected.recognition.confidence });
        expect(r.recognition.dropped.map((d) => d.id + ':' + d.rule)).toEqual(expected.recognition.dropped);
        expect(r.recognition.unverified === true).toBe(expected.recognition.unverified);
      } else expect(r.recognition).toBeNull();
    });
  }
  it('the engine itself still agrees with the recorded expectations', () => {
    for (const name of fixtures) {
      const { files, options, expected } = load(name);
      const r = verifyBundleFiles(files, { ...options, diagnose: true });
      expect(r.ok, name).toBe(expected.ok);
      expect(r.checks.map((c) => c.name + ':' + c.ok), name).toEqual(expected.checks.map((c) => c.name + ':' + c.ok));
    }
  });
  it('reads a zip (stored and deflated entries) and verifies the tree inside it', async () => {
    const { files, options } = load('honest-plain');
    const entries = [...files].map(([name, text], i) => ({ name, data: Buffer.from(text), method: i % 2 ? 8 : 0 }));
    const parts = [], central = []; let off = 0;
    for (const e of entries) {
      const raw = e.data, body = e.method === 8 ? deflateRawSync(raw) : raw, nm = Buffer.from(e.name), crc = crc32(raw);
      const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.method, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nm.length, 26);
      const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(e.method, 10); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
      parts.push(lh, nm, body); central.push(ch, nm); off += 30 + nm.length + body.length;
    }
    const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
    const zip = Buffer.concat([...parts, cd, end]);
    const back = await V.readZip(zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.length));
    expect([...back.keys()].sort()).toEqual([...files.keys()].sort());
    const r = await V.verifyTree(back, options);
    expect(r.ok).toBe(true);
    // a folder picked from a parent (every path prefixed by a folder name) works too
    const prefixed = new Map([...files].map(([k, v]) => ['picked/' + k, v]));
    expect((await V.verifyTree(prefixed, options)).ok).toBe(true);
  });
  it('refuses garbage and archives with path tricks', async () => {
    await expect(V.readZip(new Uint8Array(100).buffer)).rejects.toThrow(/not a zip/);
    const r = await V.verifyTree(new Map([['x.txt', 'y']]), {});
    expect(r.ok).toBe(false); expect(r.checks[0].name).toBe('bundle-files');
  });
});
