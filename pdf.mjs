// Builds dist/spec/SANAD-SPEC-0.1.pdf from the printed spec page with Chrome. Run after build.mjs.
import { chromium } from 'playwright-core';
import { serve } from './lib/serve.mjs';
const srv = await serve('dist'); const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage(); await p.goto(srv.url + '/spec/0.1/'); await p.emulateMedia({ media: 'print' });
await p.pdf({ path: 'spec/SANAD-SPEC-0.1.pdf', format: 'A4', printBackground: true, preferCSSPageSize: true, tagged: true, outline: true });
import('node:fs').then((fs) => fs.cpSync('spec/SANAD-SPEC-0.1.pdf', 'dist/spec/SANAD-SPEC-0.1.pdf')); console.log('spec/SANAD-SPEC-0.1.pdf'); await b.close(); srv.close();
