// Renders the social preview image (1200x630) with Chrome: node social.mjs
import { chromium } from 'playwright-core';
import { LOGO_MARK, LOGO_WORD } from './lib/layout.mjs';
const html = `<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;width:1200px;height:630px;background:#003B73;color:#fff;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif}
.f{position:absolute;inset:0;border-top:0;padding:72px 84px;display:flex;flex-direction:column;justify-content:space-between}
.logo{height:64px;width:auto;color:#fff;align-self:flex-start}
h1{font-size:62px;line-height:1.12;font-weight:600;margin:0;max-width:960px;letter-spacing:-.01em}
.sub{font-size:28px;line-height:1.4;color:#D6E3F2;max-width:900px;margin:22px 0 0}
.row{display:flex;justify-content:space-between;align-items:flex-end;font-size:24px;color:#D6E3F2;border-top:2px solid #4A78A8;padding-top:22px}
</style><div class="f"><svg class="logo" viewBox="0 0 192 32">${LOGO_MARK}${LOGO_WORD}</svg>
<div><h1>An open protocol for recomputable recognition of skills</h1><p class="sub">A chain of claim, evidence and signed attestations that anyone can recompute under their own policy. No token. Not accreditation.</p></div>
<div class="row"><span>sanadprotocol.org</span><span>Draft v0.1 · 7 November 2026</span></div></div>`;
const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({ viewport: { width: 1200, height: 630 } }); await p.setContent(html); await p.screenshot({ path: 'assets/social-preview.png' }); await b.close(); console.log('assets/social-preview.png');
