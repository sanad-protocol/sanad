// Builds the static site into dist/. Content: content/<lang>/*.md (front matter + markdown) and spec/SPEC-v0.1.md.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, cpSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { Marked } from 'marked';
import { SITE, LANGS, T, DATE_LONG } from './lib/i18n.mjs';
import { render, esc, LOGO_MARK, LOGO_WORD } from './lib/layout.mjs';

const OUT = 'dist';
rmSync(OUT, { recursive: true, force: true }); mkdirSync(OUT, { recursive: true });

const slug = (s) => s.toLowerCase().replace(/<[^>]*>/g, '').replace(/&[a-z]+;/g, '').replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-+|-+$/g, '') || 'section';

function frontMatter(src) {
  const m = /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/.exec(src); if (!m) throw new Error('missing front matter');
  const fm = {}; for (const line of m[1].split('\n')) { const i = line.indexOf(':'); if (i > 0) fm[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
  return [fm, m[2]];
}

function footnotes(md, lang) {
  const defs = new Map(); md = md.replace(/^\[\^([\w-]+)\]:\s*(.+)$/gm, (_, id, text) => { defs.set(id, text); return ''; });
  const order = []; md = md.replace(/\[\^([\w-]+)\]/g, (_, id) => { if (!defs.has(id)) return _; if (!order.includes(id)) order.push(id); const n = order.indexOf(id) + 1; return `<sup class="fn"><a id="fnref-${n}" href="#fn-${n}" aria-label="${T[lang].notes} ${n}">${n}</a></sup>`; });
  return [md, order.length ? `<section class="footnotes" aria-labelledby="fn-h"><h2 id="fn-h">${esc(T[lang].notes)}</h2><ol>${order.map((id, i) => `<li id="fn-${i + 1}">${defs.get(id)} <a class="back" href="#fnref-${i + 1}" aria-label="${esc(T[lang].fnback)} ${i + 1}">↑</a></li>`).join('')}</ol></section>` : ''];
}

const PERSIAN = '۰۱۲۳۴۵۶۷۸۹';
/** In right-to-left pages: isolate Latin tokens and codes (so that they keep their order) and, for Persian, write digits as Persian digits. */
function rtlFix(html, lang) {
  const TOKEN = /[A-Za-z0-9][A-Za-z0-9_.:\/+#@-]*(?: [A-Za-z0-9][A-Za-z0-9_.:\/+#@-]*)*/g; let skip = 0;
  return html.split(/(<[^>]+>)/).map((seg) => {
    if (seg.startsWith('<')) { if (/^<(code|pre|script|bdi)\b/.test(seg)) skip++; else if (/^<\/(code|pre|script|bdi)>/.test(seg)) skip = Math.max(0, skip - 1); return seg.replace(/^<code\b(?![^>]*dir=)/, '<code dir="ltr"'); }
    if (skip) return seg;
    return seg.replace(TOKEN, (full) => {
      const m = /^(.*?)([.:/#+@_-]*)$/.exec(full); const t = m[1], tail = m[2]; // trailing punctuation stays outside the isolated token
      if (/[A-Za-z]/.test(t)) return `<bdi dir="ltr">${t}</bdi>${tail}`;
      if (lang === 'fa') return t.replace(/\./g, '٫').replace(/[0-9]/g, (d) => PERSIAN[d]) + tail;
      return (/[.:/-]/.test(t) ? `<bdi dir="ltr">${t}</bdi>` : t) + tail;
    });
  }).join('');
}
function mdToHtml(md, lang) {
  const headings = []; const used = new Set(); let lastH = ''; let tn = 0; const m = new Marked({ gfm: true, breaks: true });
  m.use({ renderer: {
    heading({ tokens, depth }) { const html = this.parser.parseInline(tokens); let id = slug(html); let n = 2; const base = id; while (used.has(id)) id = `${base}-${n++}`; used.add(id); if (depth >= 2 && depth <= 3) headings.push({ level: depth, id, html }); lastH = html.replace(/<[^>]*>/g, ''); return `<h${depth} id="${id}">${html}<a class="anchor" href="#${id}" aria-label="${esc(T[lang].anchor)}: ${esc(html.replace(/<[^>]*>/g, ''))}">§</a></h${depth}>\n`; },
    table(token) { const head = this.tablerow({ text: token.header.map((c) => this.tablecell(c)).join('') }); const body = token.rows.map((r) => this.tablerow({ text: r.map((c) => this.tablecell(c)).join('') })).join(''); tn++; return `<div class="tablewrap" role="region" tabindex="0" aria-label="${esc((lastH || 'Table') + ' (table ' + tn + ')')}"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>\n`; },
    code({ text, lang: l }) { return `<pre tabindex="0"><code${l ? ` class="language-${esc(l)}"` : ''}>${esc(text)}</code></pre>\n`; },
    link({ href, title, tokens }) { const inner = this.parser.parseInline(tokens); const ext = /^https?:\/\//.test(href) && !href.startsWith(SITE.url); return `<a href="${esc(href)}"${title ? ` title="${esc(title)}"` : ''}${ext ? ' rel="noopener" class="ext"' : ''}>${inner}${ext ? `<span class="vh"> (${esc(T[lang].external)})</span>` : ''}</a>`; },
  } });
  const out = m.parse(md); return [LANGS[lang].dir === 'rtl' ? rtlFix(out, lang) : out, headings];
}

const ref = await import('./reference/dist/sanad-reference.mjs');
function workedExample() {
  const c = ref.sampleCredential(); const r = ref.recognise(c, ref.DEFAULT_POLICY); const names = ref.SAMPLE_NAMES; const dropped = new Map(r.dropped.map((d) => [d.id, d.reason]));
  const KIND = { auto: 'Practice runs (replayable)', sitting: 'Live sitting', artifact: 'Reviewed work', peer: 'Peer review' };
  const rows = c.evidence.map((e) => { const att = c.attestations.filter((a) => a.evidence === e.id); const who = att.length ? att.map((a) => `${esc(names[a.attestor] ?? a.attestor)}: level ${a.level}${dropped.has(a.id) ? ` <strong>ignored</strong> (${esc(dropped.get(a.id))})` : ''}`).join('<br>') : 'replayed from seeds, no attestor needed'; return `<tr><td>${esc(e.id)}</td><td>${esc(KIND[e.kind] ?? e.kind)}<br><span class="small">${esc(e.summary)}</span></td><td>${who}</td></tr>`; }).join('');
  const steps = r.explanation.map((s) => `<li><strong>${s.rule}</strong> ${esc(s.summary)}</li>`).join('');
  return `<section class="example" aria-labelledby="ex-h"><h2 id="ex-h">A worked example</h2><p>An invented learner claims level 4 in a first course in real analysis. The verifier applies the default policy: at least two admissible attestors, one live sitting, attestors with at least three sittings.</p>
<div class="tablewrap" role="region" tabindex="0" aria-label="Evidence of the worked example"><table><caption>Evidence and attestations</caption><thead><tr><th scope="col">Item</th><th scope="col">Kind</th><th scope="col">Attestations</th></tr></thead><tbody>${rows}</tbody></table></div>
<p class="result" role="status"><span class="pill ok">${esc(r.status)}</span> level <strong>${r.level}</strong> of 5 · confidence <strong>${r.confidence}</strong> · ${r.explanation.find((s) => s.rule === 'R5')?.summary.match(/^\d+/)?.[0] ?? ''} independent attestors · live sitting present</p>
<details><summary>Show the step-by-step explanation (rules R1 to R7)</summary><ol class="steps-list">${steps}</ol></details>
<p class="small">All people and data are invented. The result is computed when this page is built, by the reference code in <code>reference/</code>; <code>node reference/verify.mjs</code> reproduces it. <a href="/spec/0.1/#appendix-a-worked-example">Appendix A</a> of the specification describes the same example.</p></section>`;
}
const pages = [];
function addPage(p) { pages.push(p); }

// ---- content pages
for (const lang of Object.keys(LANGS)) {
  const dir = join('content', lang); if (!existsSync(dir)) continue;
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.md')).sort()) {
    const [fm, raw] = frontMatter(readFileSync(join(dir, f), 'utf8'));
    let body = raw, glance = '';
    body = body.replace(/<!-- glance -->([\s\S]*?)<!-- \/glance -->/, (_, g) => { glance = g.trim(); return ''; });
    const [md2, fn] = footnotes(body, lang);
    let [html, headings] = mdToHtml(md2, lang); html = html.replace('<!-- worked-example -->', workedExample());
    const [gl] = glance ? mdToHtml(glance, lang) : [''];
    const meta = fm.docid ? { id: fm.docid, version: fm.version || '0.1', status: fm.status, licence: fm.licence } : undefined;
    addPage({ lang, key: fm.key, path: fm.path, title: fm.title, h1: fm.h1, short: fm.short, description: fm.description, nav: fm.nav, template: fm.template, numbered: fm.numbered === 'true', toc: fm.toc === 'true', tocItems: headings.filter((h) => h.level <= 3), crumbs: fm.crumbs ? JSON.parse(fm.crumbs) : [], meta, lead: fm.lead ? mdToHtml(fm.lead, lang)[0].replace(/^<p>|<\/p>\n?$/g, '') : '', glance: gl, html, footnotes: fn, stamp: fm.stamp });
  }
}

// ---- specification (rendered from the markdown source)
{
  const src = readFileSync('spec/SPEC-v0.1.md', 'utf8');
  const title = /^# (.+)$/m.exec(src)[1];
  let body = src.replace(/^# .+\n+/, '').replace(/^Document: .+\n+/m, '');
  const parts = body.split(/\n\n/); const first = parts.shift(); const [noteHtml] = mdToHtml(first, 'en'); body = parts.join('\n\n');
  const [html0, headings] = mdToHtml(body, 'en'); const html = `<aside class="note">${noteHtml}</aside>\n` + html0;
  addPage({ lang: 'en', key: 'spec-0.1', path: '/spec/0.1/', title: 'Sanad v0.1: specification (draft)', h1: title, short: 'Version 0.1', description: 'Sanad v0.1 draft: data model, recognition function, transparency log, privacy and threats of an open protocol for recomputable recognition of skills.', nav: 'spec', template: 'doc spec', toc: true, tocItems: headings, crumbs: [['Specification', '/spec/']], meta: { id: 'SANAD-SPEC-0.1', version: '0.1 (draft)' }, cover: { subtitle: 'Specification · Spezifikation' }, html,
    jsonld: { '@context': 'https://schema.org', '@type': 'TechArticle', headline: title, inLanguage: 'en', datePublished: SITE.stand, author: { '@type': 'Person', name: 'Arash Kermani Kolankeh' }, publisher: { '@type': 'Organization', name: 'Sanad', url: SITE.url }, license: 'https://creativecommons.org/licenses/by/4.0/', url: SITE.url + '/spec/0.1/' } });
}
// home gets Organization JSON-LD
for (const p of pages) if (p.path === '/' ) p.jsonld = { '@context': 'https://schema.org', '@type': 'Organization', name: 'Sanad', url: SITE.url, description: 'An open protocol for recomputable recognition of skills (draft).', logo: SITE.url + '/assets/logo-color.svg', founder: { '@type': 'Person', name: 'Arash Kermani Kolankeh' } };

// ---- indexes
const pagesByKey = new Map(); for (const p of pages) { if (!pagesByKey.has(p.key)) pagesByKey.set(p.key, []); pagesByKey.get(p.key).push(p); }
const seenPaths = new Set();
for (const p of pages) {
  if (seenPaths.has(p.path)) throw new Error('duplicate path ' + p.path); seenPaths.add(p.path);
  const file = p.path === '/404.html' ? join(OUT, '404.html') : join(OUT, p.path, 'index.html');
  mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, render(p, { pagesByKey }));
}

// ---- assets
mkdirSync(join(OUT, 'assets'), { recursive: true }); cpSync('assets', join(OUT, 'assets'), { recursive: true });
const svg = (inner, color, bg) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 32" width="768" height="128" role="img" aria-label="Sanad">${bg ? `<rect width="192" height="32" fill="${bg}"/>` : ''}<g color="${color}">${inner}</g></svg>\n`;
writeFileSync(join(OUT, 'assets/logo-color.svg'), svg(LOGO_MARK + LOGO_WORD, '#003B73'));
writeFileSync(join(OUT, 'assets/logo-black.svg'), svg(LOGO_MARK + LOGO_WORD, '#000000'));
writeFileSync(join(OUT, 'assets/logo-reversed.svg'), svg(LOGO_MARK + LOGO_WORD, '#FFFFFF', '#003B73'));
writeFileSync(join(OUT, 'favicon.svg'), `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 32"><rect width="64" height="32" fill="#003B73"/><g color="#FFFFFF">${LOGO_MARK}</g></svg>\n`);

// ---- feeds and machine-readable files
const news = JSON.parse(readFileSync('news.json', 'utf8'));
const atom = `<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en"><title>Sanad: news</title><subtitle>Changes to the Sanad specification, website and project.</subtitle><link href="${SITE.url}/atom.xml" rel="self" type="application/atom+xml"/><link href="${SITE.url}/news/" rel="alternate" type="text/html"/><id>${SITE.url}/</id><updated>${news[0].date}T00:00:00Z</updated><author><name>Arash Kermani Kolankeh</name></author>\n${news.map((n) => `<entry><title>${esc(n.title)}</title><link href="${SITE.url}/news/#${n.id}" rel="alternate"/><id>${SITE.url}/news/#${n.id}</id><updated>${n.date}T00:00:00Z</updated><summary>${esc(n.summary)}</summary></entry>`).join('\n')}\n</feed>\n`;
writeFileSync(join(OUT, 'atom.xml'), atom);
const loc = (p) => SITE.url + (p.path === '/404.html' ? '/404.html' : p.path);
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${pages.filter((p) => p.path !== '/404.html').map((p) => { const alts = pagesByKey.get(p.key); return `<url><loc>${loc(p)}</loc><lastmod>${SITE.stand}</lastmod>${alts.length > 1 ? alts.map((a) => `<xhtml:link rel="alternate" hreflang="${a.lang}" href="${loc(a)}"/>`).join('') : ''}</url>`; }).join('\n')}\n</urlset>\n`;
writeFileSync(join(OUT, 'sitemap.xml'), sitemap);
writeFileSync(join(OUT, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${SITE.url}/sitemap.xml\n`);
mkdirSync(join(OUT, '.well-known'), { recursive: true });
writeFileSync(join(OUT, '.well-known/security.txt'), `Contact: mailto:security@sanadprotocol.org\nExpires: 2027-11-07T00:00:00.000Z\nPreferred-Languages: en, de\nCanonical: ${SITE.url}/.well-known/security.txt\nPolicy: ${SITE.url}/participate/#security\n`);
writeFileSync(join(OUT, 'humans.txt'), `/* TEAM */\nSteward: Arash Kermani Kolankeh\nSite: sanadprotocol.org\n\n/* SITE */\nLast update: 2026/11/07\nLanguage: English, Deutsch, العربية, فارسی\nStandards: HTML5, CSS3, WCAG 2.2 AA (target)\nComponents: no scripts, no cookies, no external requests\n`);
if (existsSync('spec/SANAD-SPEC-0.1.pdf')) cpSync('spec/SANAD-SPEC-0.1.pdf', join(OUT, 'spec/SANAD-SPEC-0.1.pdf'));
writeFileSync(join(OUT, 'CNAME'), 'sanadprotocol.org\n'); writeFileSync(join(OUT, '.nojekyll'), '');
console.log(pages.length + ' pages built into ' + OUT);
export { pages };
