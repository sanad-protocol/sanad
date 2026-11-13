// Builds the single-file verifier page: node engine/verifiers/browser/build.mjs  ->  sanad-verifier.html (core + verifier + page inlined, no external reference).
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
export function buildHtml() {
  let core = readFileSync(join(here, '../../../reference/dist/sanad-reference.mjs'), 'utf8');
  const i = core.lastIndexOf('\nexport {');
  if (i < 0) throw new Error('unexpected core bundle layout');
  core = core.slice(0, i) + '\n';
  const wrapped = 'const SANAD_CORE = (() => {\n' + core + 'return { canonical, hashOf, recognise, policyProblems, attestationPayload, sha256Hex };\n})();';
  const esc = (s) => s.replace(/<\/script/gi, '<\\/script');
  return readFileSync(join(here, 'template.html'), 'utf8')
    .replace('/*__CORE__*/', () => esc(wrapped))
    .replace('/*__VERIFIER__*/', () => esc(readFileSync(join(here, 'verifier.js'), 'utf8')))
    .replace('/*__UI__*/', () => esc(readFileSync(join(here, 'ui.js'), 'utf8')));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const html = buildHtml();
  writeFileSync(join(here, 'sanad-verifier.html'), html);
  console.log('sanad-verifier.html ' + html.length + ' bytes');
}
