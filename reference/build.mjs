// Bundles the reference implementation into one dependency-free ES module: node reference/build.mjs
import { build } from 'esbuild';
await build({ entryPoints: ['reference/src/index.ts'], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022', outfile: 'reference/dist/sanad-reference.mjs', legalComments: 'none', banner: { js: '// Sanad v0.1 reference implementation (Apache-2.0). Generated from reference/src by reference/build.mjs.' } });
console.log('reference/dist/sanad-reference.mjs');
