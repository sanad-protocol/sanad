// Bundles engine/src/index.mjs into one dependency-free file: node engine/build.mjs
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const OUT = resolve(here, 'dist/sanad-engine.mjs');
export const BANNER = '// Sanad engine 0.2.0, algorithm sanad-0.1 (Apache-2.0). Generated from engine/src by engine/build.mjs.';

/** Returns the bundle text without writing it. */
export async function bundleText() {
  const r = await build({
    entryPoints: [resolve(here, 'src/index.mjs')], bundle: true, format: 'esm', platform: 'node', target: 'node22',
    legalComments: 'none', banner: { js: BANNER }, write: false, outfile: OUT, logLevel: 'silent',
  });
  return r.outputFiles[0].text;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const text = await bundleText();
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, text);
  console.log('engine/dist/sanad-engine.mjs');
  console.log('sha256 ' + createHash('sha256').update(text).digest('hex'));
}
