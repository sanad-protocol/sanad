import { SITE, LANGS, T, DATE_LONG } from './i18n.mjs';

export const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const abs = (p) => SITE.url + p;

/** The logo lockup as inline SVG: a mark of three linked squares (claim, evidence, attestation; the last one filled) and the word SANAD drawn as light strokes, so it renders the same everywhere. */
export const LOGO_MARK = `<g fill="none" stroke="currentColor" stroke-width="2.6" stroke-linejoin="round"><rect x="2" y="9" width="14" height="14" rx="2"/><path d="M16 16h9"/><rect x="25" y="9" width="14" height="14" rx="2"/><path d="M39 16h9"/><rect x="48" y="9" width="14" height="14" rx="2" fill="currentColor"/></g>`;
export const LOGO_WORD = `<g fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="square" stroke-linejoin="miter" transform="translate(76 6)"><path d="M17 6.5C14.5 3 5 3 5 8.6c0 5.8 12.4 3.2 12.4 9.2 0 5.6-9.6 5.9-13 1.6"/><path d="M26 24 33.5 3.5 41 24M29 17.5h9"/><path d="M50 24V3.5L64 24V3.5"/><path d="M73 24 80.5 3.5 88 24M76 17.5h9"/><path d="M97 3.5V24h5.5c10.5 0 10.5-20.5 0-20.5Z"/></g>`;
export const logoSvg = (cls = 'logo', title = 'Sanad') => `<svg class="${cls}" viewBox="0 0 192 32" role="img" aria-label="${esc(title)}" focusable="false">${LOGO_MARK}${LOGO_WORD}</svg>`;


const REPO = 'https://github.com/sanad-protocol/sanad';
// Footer columns (English and German). [label, href, key of the page (to mark pages that exist only in English)]
const FOOT = {
  en: [
    ['Specification', [['Version 0.1 (HTML)', '/spec/0.1/'], ['Version 0.1 (PDF)', '/spec/SANAD-SPEC-0.1.pdf'], ['Conformance', '/conformance/'], ['Reference implementation', REPO + '/tree/main/reference'], ['Explainer', '/explainer/'], ['Glossary', '/glossary/']]],
    ['Project', [['Governance', '/governance/'], ['Roadmap', '/roadmap/'], ['Participate', '/participate/'], ['Support', '/support/'], ['About', '/about/'], ['News', '/news/'], ['Clarifications', '/faq/']]],
    ['Legal', [['Legal notice', '/legal-notice/', 'legal'], ['Privacy', '/privacy/', 'privacy'], ['Accessibility', '/accessibility/', 'accessibility'], ['Licence', '/license/', 'license'], ['Intellectual property', '/ipr/'], ['Security', '/security/']]],
    ['Contact', [['Contact form', '/contact/'], ['info@sanadprotocol.org', 'mailto:info@sanadprotocol.org'], ['Repository', REPO], ['Report an issue', REPO + '/issues']]],
  ],
  de: [
    ['Spezifikation', [['Version 0.1 (HTML)', '/spec/0.1/'], ['Version 0.1 (PDF)', '/spec/SANAD-SPEC-0.1.pdf'], ['Konformität', '/conformance/'], ['Referenzimplementierung', REPO + '/tree/main/reference'], ['Erklärseite', '/explainer/'], ['Glossar', '/glossary/']]],
    ['Projekt', [['Governance', '/governance/'], ['Fahrplan', '/roadmap/'], ['Mitmachen', '/de/mitmachen/', 'participate'], ['Unterstützen', '/support/'], ['Über', '/de/ueber/'], ['Neuigkeiten', '/news/'], ['Fragen und Antworten', '/faq/']]],
    ['Rechtliches', [['Impressum', '/de/impressum/', 'legal'], ['Datenschutz', '/de/datenschutz/', 'privacy'], ['Barrierefreiheit', '/de/barrierefreiheit/', 'accessibility'], ['Lizenz', '/de/lizenz/', 'license'], ['Schutzrechte', '/ipr/'], ['Sicherheit', '/security/']]],
    ['Kontakt', [['Kontaktformular', '/de/kontakt/'], ['info@sanadprotocol.org', 'mailto:info@sanadprotocol.org'], ['Repository', REPO], ['Problem melden', REPO + '/issues']]],
  ],
};
const UI = {
  en: { ribbon: ['Version 0.1', 'Not accreditation', 'Decentralised assessment'], asof: 'As of', menu: 'Menu', tagline: 'Open protocol for recomputable recognition of skills', updated: 'Last updated', licenceLine: 'Text: CC BY 4.0 · Code: Apache-2.0', statusLine: 'Sanad is an open protocol. It is not accreditation and has no token. The Open Sanad Foundation (UAE) is in preparation; until it exists the author acts as interim steward and a second steward is being appointed.', more: 'More', top: 'Back to top', normative: 'Normative', informative: 'Informative' },
  de: { ribbon: ['Version 0.1', 'Keine Akkreditierung', 'Dezentrale Bewertung'], asof: 'Stand', menu: 'Menü', tagline: 'Offenes Protokoll zur nachrechenbaren Anerkennung von Fähigkeiten', updated: 'Zuletzt aktualisiert', licenceLine: 'Text: CC BY 4.0 · Code: Apache-2.0', statusLine: 'Sanad ist ein offenes Protokoll. Es ist keine Akkreditierung und hat kein Token. Die Open Sanad Foundation (VAE) ist in Vorbereitung; bis dahin handelt der Autor als kommissarischer Verantwortlicher, eine zweite verantwortliche Person wird gewonnen.', more: 'Mehr', top: 'Nach oben', normative: 'Normativ', informative: 'Informativ' },
};

function langSwitch(page, pagesByKey, lang) {
  const alts = pagesByKey.get(page.key) || [];
  const items = Object.values(LANGS).map((L) => {
    const alt = alts.find((p) => p.lang === L.code);
    const target = alt ? alt.path : L.code === 'en' ? '/' : `/${L.code}/`;
    const cur = L.code === page.lang;
    return `<li><a href="${target}" hreflang="${L.code}" lang="${L.code}"${cur ? ' aria-current="true"' : ''}${alt ? '' : ' class="fallback"'} title="${esc(L.name)}">${['ar', 'fa'].includes(L.code) ? esc(L.name) : L.short}</a></li>`;
  });
  return `<nav class="langs" aria-label="${esc(T[lang].lang)}"><ul>${items.join('')}</ul></nav>`;
}

export function render(page, ctx) {
  const { pagesByKey } = ctx; const lang = page.lang; const L = LANGS[lang]; const t = T[lang]; const u = UI[lang] ?? UI.en;
  const homePath = lang === 'en' ? '/' : `/${lang}/`;
  const alts = pagesByKey.get(page.key) || [page];
  const hreflangs = alts.map((p) => `<link rel="alternate" hreflang="${p.lang}" href="${abs(p.path)}">`).join('\n') + (alts.find((p) => p.lang === 'en') ? `\n<link rel="alternate" hreflang="x-default" href="${abs(alts.find((p) => p.lang === 'en').path)}">` : '');
  const link = ([k, label, href]) => { const own = (pagesByKey.get(k) || []).some((p) => p.lang === lang); const en = lang !== 'en' && !own; return `<li><a href="${href}"${page.nav === k ? ' aria-current="page"' : ''}${en ? ' hreflang="en"' : ''}>${esc(label)}${en ? `<span class="entag" role="img" aria-label="${esc(t.enonly)}">EN</span>` : ''}</a></li>`; };
  const nav = t.nav.map(link).join(''); const more = t.more.map(link).join('');
  const crumbs = page.path === homePath ? '' : `<nav class="crumbs" aria-label="${esc(t.breadcrumb)}"><ol><li><a href="${homePath}">${esc(t.home)}</a></li>${(page.crumbs || []).map(([label, href]) => `<li><a href="${href}">${esc(label)}</a></li>`).join('')}<li aria-current="page">${esc(page.short || page.title)}</li></ol></nav>`;
  const status = (page.meta && page.meta.status) || t.draft;
  const metaBlock = page.meta ? `<dl class="docmeta"><div><dt>${t.doc}</dt><dd>${esc(page.meta.id)}</dd></div><div><dt>${t.version}</dt><dd>${esc(page.meta.version)}</dd></div><div><dt>${t.status}</dt><dd><span class="badge draft">${esc(status)}</span></dd></div><div><dt>${t.date}</dt><dd><time datetime="${SITE.stand}">${DATE_LONG[lang]}</time></dd></div><div><dt>${t.licence}</dt><dd>${esc(page.meta.licence || 'CC BY 4.0')}</dd></div></dl>` : '';
  const bannerHead = { de: 'Übersetzung' };
  const banner = lang !== 'en' ? `<p class="transbanner" role="note"><strong>${bannerHead[lang]}.</strong> ${esc(t.translation)} ${esc(t.ennote)}</p>` : '';
  const toc = page.toc && page.tocItems?.length ? `<nav class="toc" aria-label="${esc(t.onthispage)}"><h2>${esc(t.onthispage)}</h2><ol>${page.tocItems.map((i) => `<li class="l${i.level}"><a href="#${i.id}">${i.html}</a></li>`).join('')}</ol></nav>` : '';
  const glance = page.glance ? `<aside class="glance" aria-labelledby="glance-h"><h2 id="glance-h">${esc(t.glance)}</h2>${page.glance}</aside>` : '';
  const cover = page.cover ? `<section class="print-cover" aria-hidden="true"><p class="pc-org">Sanad</p><p class="pc-title">${esc(page.h1 || page.title)}</p><p class="pc-sub">${esc(page.cover.subtitle)}</p><dl><div><dt>Document</dt><dd>${esc(page.meta.id)}</dd></div><div><dt>Status</dt><dd>Open for comment</dd></div><div><dt>Version</dt><dd>${esc(page.meta.version)}</dd></div><div><dt>Date</dt><dd>${DATE_LONG.en}</dd></div><div><dt>Licence</dt><dd>${esc(page.meta.licence || 'CC BY 4.0')}</dd></div><div><dt>Steward</dt><dd>Kermani Kolankeh, Arash</dd></div><div><dt>URL</dt><dd>${esc(abs(page.path))}</dd></div></dl><p class="pc-note">Sanad is not accreditation.</p></section>` : '';
  const ld = page.jsonld ? `<script type="application/ld+json">${JSON.stringify(page.jsonld)}</script>` : '';
  const canon = abs(page.path);
  const og = `<meta property="og:type" content="${page.path === '/' ? 'website' : 'article'}"><meta property="og:site_name" content="Sanad"><meta property="og:title" content="${esc(page.title)}"><meta property="og:description" content="${esc(page.description)}"><meta property="og:url" content="${canon}"><meta property="og:locale" content="${L.og}"><meta property="og:image" content="${abs('/assets/social-preview.png')}"><meta property="og:image:alt" content="Sanad: an open protocol for recomputable recognition of skills"><meta name="twitter:card" content="summary_large_image">`;
  const ribbon = `<div class="ribbon" role="region" aria-label="${lang === 'de' ? 'Status dieses Dokuments' : 'Status of this document'}"><div class="wrap"><ul>${u.ribbon.map((x, i) => `<li${i === 0 ? ' class="first"' : ''}>${esc(x)}</li>`).join('')}</ul><span>${esc(u.asof)} <time datetime="${SITE.stand}">${DATE_LONG[lang]}</time></span></div></div>`;
  const header = `<header class="site"><div class="wrap bar">
<a class="brand" href="${homePath}">${logoSvg('logo', 'Sanad')}<span class="tagline">${esc(u.tagline)}</span></a>
<nav class="primary" aria-label="${esc(t.menu)}"><ul>${nav}<li class="more"><details><summary>${esc(t.moreLabel)}</summary><ul>${more}</ul></details></li></ul></nav>
<div class="tools">${langSwitch(page, pagesByKey, lang)}<details class="mobilemenu"><summary>${esc(u.menu)}</summary><nav aria-label="${esc(t.menu)} (${esc(u.menu)})"><ul>${nav}${more}</ul></nav></details></div>
</div></header>`;
  const cols = FOOT[lang];
  const footLink = ([label, href, key]) => { const own = key ? (pagesByKey.get(key) || []).some((p) => p.lang === lang) : true; const en = lang === 'de' && !own; const ext = /^https?:/.test(href) && !href.startsWith(SITE.url); return `<li><a href="${href}"${ext ? ' rel="noopener" class="ext"' : ''}${en ? ' hreflang="en"' : ''}>${esc(label)}${en ? '<span class="entag" role="img" aria-label="englisch">EN</span>' : ''}</a></li>`; };
  const footer = cols ? `<footer class="site"><div class="wrap">
<div class="fgrid"><div class="fbrand">${logoSvg('logo', 'Sanad')}<p>${esc(u.statusLine)}</p></div>${cols.map(([h, items]) => `<nav aria-label="${esc(h)}"><h2>${esc(h)}</h2><ul>${items.map(footLink).join('')}</ul></nav>`).join('')}</div>
<div class="fbase"><span>${esc(u.licenceLine)}</span><span>sanadprotocol.org · ${esc(t.stand)} ${DATE_LONG[lang]}</span><a href="#main">${esc(u.top)}</a></div></div></footer>`
    : `<footer class="site"><div class="wrap"><p class="fline">${esc(t.footerLine)}</p><ul class="flinks"><li><a href="/legal-notice/">${esc(t.footerLegal)}</a></li><li><a href="/privacy/">${esc(t.footerPrivacy)}</a></li><li><a href="/accessibility/">${esc(t.footerAccess)}</a></li><li><a href="/contact/">${esc(t.footerContact)}</a></li><li><a href="/license/">${esc(t.footerLicence)}</a></li></ul><p class="fsmall">sanadprotocol.org · ${esc(t.stand)} ${DATE_LONG[lang]} · <a href="#main">${esc(t.back)}</a></p></div></footer>`;
  const updated = `<p class="updated">${esc(u.updated)}: <time datetime="${SITE.stand}">${DATE_LONG[lang]}</time></p>`;
  const main = page.template && page.template.startsWith('home') ? `<main id="main">${banner ? `<div class="wrap">${banner}</div>` : ''}${page.html}</main>` : `<main id="main" class="wrap">
${banner}
${crumbs}
<article>
<h1>${esc(page.h1 || page.title)}</h1>
${page.lead ? `<p class="lead">${page.lead}</p>` : ''}
${metaBlock}
${page.actions || ''}
${glance}
<div class="cols${toc ? ' hastoc' : ''}">
${toc}
<div class="body">
${page.html}
${page.footnotes || ''}
${page.meta ? '' : updated}
</div>
</div>
</article>
</main>`;
  return `<!doctype html>
<html lang="${lang}" dir="${L.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self' data:; script-src 'self'; ${page.key === 'contact' ? 'connect-src https://rtc.kamangir.school; ' : ''}base-uri 'none'; form-action 'none'">
<title>${esc(page.title)}${page.path === homePath ? '' : ' · Sanad'}</title>
<meta name="description" content="${esc(page.description)}">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#0A3A82">
<link rel="canonical" href="${canon}">
${hreflangs}
${og}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<link rel="alternate" type="application/atom+xml" title="Sanad news" href="/atom.xml">
<link rel="stylesheet" href="/assets/style.css">
${ld}
</head>
<body class="${page.template || 'doc'}${page.numbered ? ' numbered' : ''}">
<a class="skip" href="#main">${esc(t.skip)}</a>
${ribbon}
${header}
${main}
${footer}
<script src="/assets/enhance.js" defer></script>
</body>
</html>
`;
}
