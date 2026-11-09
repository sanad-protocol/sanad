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
const PAIRS = [];
const addPairs = (pfx, ink, muted, bg, band, acc) => { for (const [n, fg, b, min] of [['text', ink, bg, 4.5], ['text on band', ink, band, 4.5], ['muted', muted, bg, 4.5], ['muted on band', muted, band, 4.5], ['accent text', acc, bg, 4.5], ['accent on band', acc, band, 4.5], ['paper on accent', bg, acc, 4.5]]) PAIRS.push([pfx + ' ' + n, fg, b, min]); };
addPairs('light', '#15181C', '#4F565F', '#FBFAF7', '#F2F0EB', '#0A3A82');
addPairs('dark', '#ECEBE7', '#A9ADB3', '#101214', '#171A1D', '#8DB0F2');
for (const [n, fg, bg, min] of PAIRS) ok(cr(fg, bg) >= min, `contrast ${n}: ${cr(fg, bg).toFixed(2)} < ${min}`);
// 6. the reference implementation passes its conformance vectors
import { spawnSync } from 'node:child_process';
const v = spawnSync('node', ['reference/verify.mjs'], { encoding: 'utf8' }); ok(v.status === 0, 'reference/verify.mjs failed:\n' + v.stdout.split('\n').filter((l) => l.startsWith('FAIL')).join('\n'));
// 7. diagrams: present in en and de, valid, two colours only, calm motion rules
const CSS = readFileSync(join(DIST, 'assets/style.css'), 'utf8');
for (const [pg, names] of [['/', ['actors', 'chain', 'verify', 'tamper']], ['/de/', ['actors', 'chain', 'verify', 'tamper']], ['/explainer/', ['verify', 'tamper']], ['/for/examiners/', ['chain']]]) {
  const src = readFileSync(join(DIST, pg, 'index.html'), 'utf8');
  for (const n of names) {
    const m = new RegExp(`<figure class="dg" id="dg-${n}"[^>]*>(<svg[\\s\\S]*?</svg>)<figcaption>`).exec(src); ok(!!m, `${pg}: diagram ${n} missing`); if (!m) continue;
    const svg = m[1];
    ok(/role="img" aria-labelledby="[\w-]+-t [\w-]+-d"/.test(svg) && /<title id="[\w-]+-t">[^<]{5,}/.test(svg) && /<desc id="[\w-]+-d">[^<]{40,}/.test(svg), `${pg}: ${n} needs title and desc`);
    ok(!/#[0-9a-fA-F]{3,6}\b|rgb\(|\sfill="|\sstroke="|\sstyle="/.test(svg), `${pg}: ${n} has colour values in markup (colours come from the two-colour CSS)`);
    const open = (svg.match(/<(rect|path|circle|text|g|title|desc)\b/g) || []).length, close = (svg.match(/<\/(text|g|title|desc)>|\/>/g) || []).length; ok(open === close, `${pg}: ${n} tags unbalanced (${open}/${close})`);
    ok((svg.match(/<svg/g) || []).length === 1 && /viewBox="0 0 \d+ \d+"/.test(svg), `${pg}: ${n} viewBox`);
  }
  ok(!/Claude|accredited|accreditation/i.test((src.match(/<figure class="dg"[\s\S]*?<\/figure>/g) || []).join('')), `${pg}: forbidden words in diagrams`);
}
ok(/Beweis|Bündel|Prüfende Stelle/.test(readFileSync(join(DIST, 'de/index.html'), 'utf8').match(/<figure class="dg" id="dg-actors"[\s\S]*?<\/figure>/)?.[0] || ''), 'de diagram carries German text');
ok(/prefers-reduced-motion:reduce\)\{\.dg \*\{animation:none!important/.test(CSS) && /prefers-reduced-motion:no-preference\)\{\s*\.dg/.test(CSS), 'reduced-motion rules for diagrams');
// exactly two colours plus neutrals in the stylesheet (outside print)
const hexes = [...new Set((CSS.split('@media print')[0].match(/#[0-9a-fA-F]{6}\b/g) || []).map((h) => h.toUpperCase()))];
const ACC = new Set(['#0A3A82', '#072B63', '#8DB0F2', '#B3CBF7']);
for (const h of hexes) { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)); const sat = (Math.max(...c) - Math.min(...c)) / 255; ok(ACC.has(h) || sat < 0.09, `colour ${h} is neither accent nor neutral`); }
ok(!/gradient|box-shadow:\s*[^n;}]/.test(CSS.replace(/box-shadow:none/g, '').replace(/box-shadow:(inset )?[\d.]+(px)? 0 0 (\d+px )?var\(--\w+\)/g, '').replace(/box-shadow:var\(--shadow\)/g, '')), 'no gradients or shadows');
if (fails.length) { console.error('FAILED\n' + fails.join('\n')); process.exit(1); }
console.log(`ok: ${html.length} pages, ${files.length} files, ${PAIRS.length} contrast pairs`);
