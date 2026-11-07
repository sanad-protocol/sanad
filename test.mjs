// Checks on the built site (run after build.mjs and pdf.mjs): links, structure, accessibility basics, CSP, feeds, contrast, reference vectors.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
const DIST = 'dist'; const fails = []; const ok = (c, m) => { if (!c) fails.push(m); };
const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const files = walk(DIST); const html = files.filter((f) => f.endsWith('.html'));
const toUrl = (f) => '/' + f.slice(DIST.length + 1).replace(/index\.html$/, '');

// 1. every internal link and asset resolves
const exists = (u) => { u = u.split('#')[0].split('?')[0]; if (!u) return true; const f = join(DIST, u); if (existsSync(f) && statSync(f).isFile()) return true; if (existsSync(join(f, 'index.html'))) return true; return false; };
const ids = new Map();
for (const f of html) { const src = readFileSync(f, 'utf8'); ids.set(toUrl(f), new Set([...src.matchAll(/ id="([^"]+)"/g)].map((m) => m[1]))); }
for (const f of html) {
  const src = readFileSync(f, 'utf8'); const here = toUrl(f);
  for (const m of src.matchAll(/(?:href|src)="([^"]+)"/g)) { const u = m[1]; if (/^(https?:|mailto:|data:)/.test(u)) continue; if (u.startsWith('#')) { ok(ids.get(here).has(u.slice(1)), `${here}: broken anchor ${u}`); continue; } ok(exists(u), `${here}: broken link ${u}`); const [path, frag] = u.split('#'); if (frag && ids.has(path)) ok(ids.get(path).has(frag), `${here}: missing anchor ${u}`); }
}
// 2. page structure
for (const f of html) {
  const src = readFileSync(f, 'utf8'); const here = toUrl(f);
  ok(/<html lang="[a-z]{2}" dir="(ltr|rtl)">/.test(src), `${here}: lang/dir`);
  ok(/<title>[^<]{3,}<\/title>/.test(src), `${here}: title`); ok((src.match(/<h1[ >]/g) || []).length === 1, `${here}: exactly one h1`);
  ok(/class="skip" href="#main"/.test(src) && /<main id="main"/.test(src), `${here}: skip link and main`);
  ok(/<meta name="description" content="[^"]{20,}"/.test(src), `${here}: description`);
  for (const img of src.matchAll(/<img\b[^>]*>/g)) ok(/ alt="/.test(img[0]), `${here}: img without alt`);
  ok(/Content-Security-Policy" content="default-src 'none'/.test(src), `${here}: CSP`);
  for (const sc of src.matchAll(/<script\b[^>]*>/g)) ok(/application\/ld\+json/.test(sc[0]) || /src="\/[^"]+"/.test(sc[0]), `${here}: only same-origin scripts are allowed (${sc[0].slice(0, 60)})`);
  ok(!/\sstyle="/.test(src), `${here}: inline style`);
  // privacy: no http(s) reference in src/href-like loading attributes except anchors
  for (const m of src.matchAll(/<(link|img|script|iframe|source|video|audio)\b[^>]*(?:src|href)="(https?:)?\/\/[^"]+"/g)) { if (!/rel="canonical"|rel="alternate"/.test(m[0])) fails.push(`${here}: external load ${m[0].slice(0, 80)}`); }
  ok(!/https?:\/\/[^"' ]*\.(woff2?|ttf|otf)/.test(src), `${here}: external font`);
  // heading order: no jump of more than one level
  let last = 1; for (const h of src.matchAll(/<h([1-6])[ >]/g)) { const n = +h[1]; ok(n <= last + 1, `${here}: heading jump h${last} to h${n}`); last = n; }
}
// 3. hreflang symmetry
const hl = new Map();
for (const f of html) { const src = readFileSync(f, 'utf8'); const self = toUrl(f); const set = [...src.matchAll(/rel="alternate" hreflang="([a-z-]+)" href="https:\/\/sanadprotocol\.org([^"]*)"/g)].map((m) => [m[1], m[2]]); hl.set(self, set); }
for (const [self, set] of hl) { if (self === '/404.html') continue; for (const [lang, path] of set) { if (lang === 'x-default') continue; const back = hl.get(path); ok(!!back && back.some(([l, p]) => p === self), `hreflang not symmetric: ${self} -> ${path}`); } }
// 4. sitemap and atom
const sm = readFileSync(join(DIST, 'sitemap.xml'), 'utf8'); for (const m of sm.matchAll(/<loc>https:\/\/sanadprotocol\.org([^<]*)<\/loc>/g)) ok(exists(m[1]), `sitemap url missing: ${m[1]}`);
ok(/^<\?xml/.test(sm) && sm.includes('</urlset>'), 'sitemap well-formed');
const at = readFileSync(join(DIST, 'atom.xml'), 'utf8'); ok(at.includes('<feed') && at.includes('</feed>') && (at.match(/<entry>/g) || []).length >= 3, 'atom feed');
for (const need of ['robots.txt', '.well-known/security.txt', 'humans.txt', 'CNAME', '.nojekyll', 'favicon.svg', 'assets/style.css', 'assets/logo-color.svg', 'assets/social-preview.png', 'spec/SANAD-SPEC-0.1.pdf']) ok(existsSync(join(DIST, need)), `missing ${need}`);
// 5. contrast of the palette (WCAG 2.2: 4.5 text, 3 for large text and graphics)
const lum = (h) => { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const cr = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const PAIRS = [['light text', '#16202D', '#FFFFFF', 4.5], ['light text on band', '#16202D', '#F4F6F9', 4.5], ['light muted on white', '#4A5668', '#FFFFFF', 4.5], ['light muted on band', '#4A5668', '#F4F6F9', 4.5], ['light muted on tint', '#4A5668', '#EAF0F7', 4.5], ['light navy on white', '#0B2E5C', '#FFFFFF', 4.5], ['light navy on tint', '#0B2E5C', '#EAF0F7', 4.5], ['light link on white', '#0B4F9C', '#FFFFFF', 4.5], ['light link on band', '#0B4F9C', '#F4F6F9', 4.5], ['light link on tint', '#0B4F9C', '#EAF0F7', 4.5], ['light accent text on white', '#0B6B73', '#FFFFFF', 4.5], ['light accent text on tint', '#0B6B73', '#EAF0F7', 4.5], ['white on navy (buttons, thead, ribbon)', '#FFFFFF', '#0B2E5C', 4.5], ['light draft badge', '#5C3D00', '#FFF3D1', 4.5], ['light ok badge', '#14532D', '#E3F4E7', 4.5], ['light deprecated badge', '#3E4958', '#E9EDF2', 4.5], ['light focus ring', '#0B5BD3', '#FFFFFF', 3], ['light status border', '#A87400', '#FFFFFF', 3],
  ['dark text', '#E4E9F0', '#0E141C', 4.5], ['dark text on band', '#E4E9F0', '#131B26', 4.5], ['dark muted on bg', '#AAB5C4', '#0E141C', 4.5], ['dark muted on band', '#AAB5C4', '#131B26', 4.5], ['dark muted on tint', '#AAB5C4', '#16263A', 4.5], ['dark navy text on bg', '#9CC2F0', '#0E141C', 4.5], ['dark navy text on tint', '#9CC2F0', '#16263A', 4.5], ['dark link on bg', '#8DB8EE', '#0E141C', 4.5], ['dark link on band', '#8DB8EE', '#131B26', 4.5], ['dark link on tint', '#8DB8EE', '#16263A', 4.5], ['dark accent on bg', '#5CC6CE', '#0E141C', 4.5], ['dark accent on tint', '#5CC6CE', '#16263A', 4.5], ['dark button text', '#0E141C', '#9CC2F0', 4.5], ['dark ribbon', '#E4E9F0', '#0A2240', 4.5], ['dark thead', '#0E141C', '#9CC2F0', 4.5], ['dark draft badge', '#F2CF7A', '#33270A', 4.5], ['dark ok badge', '#8FE3A3', '#12301C', 4.5], ['dark deprecated badge', '#B4BECB', '#1D2733', 4.5], ['dark focus ring', '#7FB1FF', '#0E141C', 3], ['dark status border', '#B98A1A', '#0E141C', 3]];
for (const [n, fg, bg, min] of PAIRS) ok(cr(fg, bg) >= min, `contrast ${n}: ${cr(fg, bg).toFixed(2)} < ${min}`);
// 6. the reference implementation passes its conformance vectors
import { spawnSync } from 'node:child_process';
const v = spawnSync('node', ['reference/verify.mjs'], { encoding: 'utf8' }); ok(v.status === 0, 'reference/verify.mjs failed:\n' + v.stdout.split('\n').filter((l) => l.startsWith('FAIL')).join('\n'));
if (fails.length) { console.error('FAILED\n' + fails.join('\n')); process.exit(1); }
console.log(`ok: ${html.length} pages, ${files.length} files, ${PAIRS.length} contrast pairs`);
