// Bundles the reference implementation into one dependency-free ES module and copies its type declarations: node reference/build.mjs
import { build } from 'esbuild';
import { copyFileSync } from 'node:fs';
await build({ entryPoints: ['reference/src/index.ts'], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022', outfile: 'reference/dist/sanad-reference.mjs', legalComments: 'none', banner: { js: '// Sanad core 0.2.0, algorithm sanad-0.1 (Apache-2.0). Generated from reference/src by reference/build.mjs.' } });
copyFileSync('reference/types/sanad-reference.d.ts', 'reference/dist/sanad-reference.d.ts');
console.log('reference/dist/sanad-reference.mjs');
