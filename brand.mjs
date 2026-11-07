// Brand assets: favicon set, app icons, web manifest and the social card (1200x630), drawn with Chrome from inline SVG. Run: node brand.mjs
import { chromium } from 'playwright-core';
import { writeFileSync } from 'node:fs';
import { LOGO_MARK, LOGO_WORD } from './lib/layout.mjs';
const NAVY = '#0B2E5C', ACCENT = '#0B6B73';
const icon = (size) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}"><rect width="32" height="32" rx="6" fill="${NAVY}"/><g fill="none" stroke="#fff" stroke-width="1.7" stroke-linejoin="round"><rect x="3" y="12" width="7" height="7" rx="1"/><path d="M10 15.5h2.5"/><rect x="12.5" y="12" width="7" height="7" rx="1"/><path d="M19.5 15.5H22"/><rect x="22" y="12" width="7" height="7" rx="1" fill="#fff"/></g></svg>`;
writeFileSync('assets/favicon.svg', icon(32));
const social = `<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;width:1200px;height:630px;background:${NAVY};color:#fff;font-family:ui-sans-serif,system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
.f{position:absolute;inset:0;padding:64px 80px;display:flex;flex-direction:column;justify-content:space-between}
.top{display:flex;align-items:center;justify-content:space-between}.logo{height:56px;width:auto;color:#fff}.tag{font-size:22px;color:#BFD3EC;letter-spacing:.02em}
h1{font-size:64px;line-height:1.1;font-weight:620;margin:0;max-width:980px;letter-spacing:-.012em}
.sub{font-size:28px;line-height:1.4;color:#D6E3F2;max-width:940px;margin:24px 0 0}
.bar{height:6px;width:96px;background:#5CC6CE;margin-bottom:28px}
.row{display:flex;justify-content:space-between;align-items:flex-end;font-size:24px;color:#BFD3EC;border-top:2px solid #3B5E8E;padding-top:20px}
.pill{border:2px solid #5CC6CE;color:#5CC6CE;border-radius:999px;padding:2px 16px;font-size:20px;font-weight:600}
</style><div class="f"><div class="top"><svg class="logo" viewBox="0 0 192 32">${LOGO_MARK}${LOGO_WORD}</svg><span class="pill">Draft v0.1</span></div>
<div><div class="bar"></div><h1>An open protocol for recomputable recognition of skills</h1><p class="sub">Data model, deterministic recognition function and conformance suite. Open specification, reference implementation, no token.</p></div>
<div class="row"><span>sanadprotocol.org</span><span>Not accreditation · decentralised assessment</span></div></div>`;
const b = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const p = await b.newPage({ viewport: { width: 1200, height: 630 } }); await p.setContent(social); await p.screenshot({ path: 'assets/social-preview.png' });
for (const [name, size] of [['favicon-32.png', 32], ['favicon-192.png', 192], ['favicon-512.png', 512], ['apple-touch-icon.png', 180]]) {
  const q = await b.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 }); await q.setContent(`<style>html,body{margin:0}</style>${icon(size).replace('rx="6"', name.startsWith('apple') ? 'rx="0"' : 'rx="6"')}`); await q.screenshot({ path: `assets/${name}`, omitBackground: true });
}
await b.close();
writeFileSync('assets/site.webmanifest', JSON.stringify({ name: 'Sanad', short_name: 'Sanad', description: 'An open protocol for recomputable recognition of skills (draft).', start_url: '/', display: 'minimal-ui', background_color: '#FFFFFF', theme_color: NAVY, icons: [{ src: '/assets/favicon-192.png', sizes: '192x192', type: 'image/png' }, { src: '/assets/favicon-512.png', sizes: '512x512', type: 'image/png' }, { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml' }] }, null, 2) + '\n');
console.log('brand assets written');
