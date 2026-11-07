import { SITE, LANGS, T, DATE_LONG } from './i18n.mjs';

export const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const abs = (p) => SITE.url + p;

/** The logo as inline SVG (mark of three linked squares and the word SANAD drawn as paths, so it renders the same everywhere). */
export const LOGO_MARK = `<g fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round"><rect x="2" y="9" width="14" height="14" rx="2"/><path d="M16 16h9"/><rect x="25" y="9" width="14" height="14" rx="2"/><path d="M39 16h9"/><rect x="48" y="9" width="14" height="14" rx="2" fill="currentColor"/></g>`;
export const LOGO_WORD = `<g fill="none" stroke="currentColor" stroke-width="3.1" stroke-linecap="square" stroke-linejoin="miter" transform="translate(76 6)"><path d="M17 6.5C14.5 3 5 3 5 8.6c0 5.8 12.4 3.2 12.4 9.2 0 5.6-9.6 5.9-13 1.6"/><path d="M26 24 33.5 3.5 41 24M29 17.5h9"/><path d="M50 24V3.5L64 24V3.5"/><path d="M73 24 80.5 3.5 88 24M76 17.5h9"/><path d="M97 3.5V24h5.5c10.5 0 10.5-20.5 0-20.5Z"/></g>`;
export const logoSvg = (cls = 'logo', title = 'Sanad') => `<svg class="${cls}" viewBox="0 0 192 32" role="img" aria-label="${esc(title)}" focusable="false">${LOGO_MARK}${LOGO_WORD}</svg>`;

function langSwitch(page, pagesByKey, lang) {
  const alts = pagesByKey.get(page.key) || [];
  const items = Object.values(LANGS).map((L) => {
    const alt = alts.find((p) => p.lang === L.code);
    const target = alt ? alt.path : L.code === 'en' ? '/' : `/${L.code}/`;
    const cur = L.code === page.lang;
    return `<li><a href="${target}" hreflang="${L.code}" lang="${L.code}"${cur ? ' aria-current="true"' : ''}${alt ? '' : ' class="fallback"'}>${L.name}</a></li>`;
  });
  return `<nav class="langs" aria-label="${esc(T[lang].lang)}"><ul>${items.join('')}</ul></nav>`;
}

export function render(page, ctx) {
  const { pagesByKey } = ctx; const lang = page.lang; const L = LANGS[lang]; const t = T[lang];
  const homePath = lang === 'en' ? '/' : `/${lang}/`;
  const alts = pagesByKey.get(page.key) || [page];
  const hreflangs = alts.map((p) => `<link rel="alternate" hreflang="${p.lang}" href="${abs(p.path)}">`).join('\n') + (alts.find((p) => p.lang === 'en') ? `\n<link rel="alternate" hreflang="x-default" href="${abs(alts.find((p) => p.lang === 'en').path)}">` : '');
  const link = ([k, label, href]) => { const own = (pagesByKey.get(k === 'name' ? 'name' : k) || []).some((p) => p.lang === lang); const en = lang !== 'en' && !own; return `<li><a href="${href}"${page.nav === k ? ' aria-current="page"' : ''}${en ? ' hreflang="en"' : ''}>${esc(label)}${en ? `<span class="entag" role="img" aria-label="${esc(t.enonly)}">EN</span>` : ''}</a></li>`; };
  const nav = t.nav.map(link).join('');
  const more = t.more.map(link).join('');
  const crumbs = page.path === homePath ? '' : `<nav class="crumbs" aria-label="${esc(t.breadcrumb)}"><ol><li><a href="${homePath}">${esc(t.home)}</a></li>${(page.crumbs || []).map(([label, href]) => `<li><a href="${href}">${esc(label)}</a></li>`).join('')}<li aria-current="page">${esc(page.short || page.title)}</li></ol></nav>`;
  const metaBlock = page.meta ? `<dl class="docmeta"><div><dt>${t.doc}</dt><dd>${esc(page.meta.id)}</dd></div><div><dt>${t.version}</dt><dd>${esc(page.meta.version)}</dd></div><div><dt>${t.status}</dt><dd>${esc(page.meta.status || t.draft)}</dd></div><div><dt>${t.date}</dt><dd><time datetime="${SITE.stand}">${DATE_LONG[lang]}</time></dd></div><div><dt>${t.licence}</dt><dd>${esc(page.meta.licence || 'CC BY 4.0')}</dd></div></dl>` : '';
  const bannerHead = { de: 'Entwurf einer Übersetzung' };
  const banner = lang !== 'en' ? `<p class="transbanner" role="note"><strong>${bannerHead[lang]}.</strong> ${esc(t.translation)} ${esc(t.ennote)}</p>` : '';
  const toc = page.toc && page.tocItems?.length ? `<nav class="toc" aria-label="${esc(t.onthispage)}"><h2>${esc(t.onthispage)}</h2><ol>${page.tocItems.map((i) => `<li class="l${i.level}"><a href="#${i.id}">${i.html}</a></li>`).join('')}</ol></nav>` : '';
  const glance = page.glance ? `<aside class="glance" aria-labelledby="glance-h"><h2 id="glance-h">${esc(t.glance)}</h2>${page.glance}</aside>` : '';
  const cover = page.cover ? `<section class="print-cover" aria-hidden="true"><p class="pc-org">Sanad</p><p class="pc-title">${esc(page.h1 || page.title)}</p><p class="pc-sub">${esc(page.cover.subtitle)}</p><dl><div><dt>Document</dt><dd>${esc(page.meta.id)}</dd></div><div><dt>Status</dt><dd>Entwurf / Draft for discussion</dd></div><div><dt>Version</dt><dd>${esc(page.meta.version)}</dd></div><div><dt>Date</dt><dd>${DATE_LONG.en}</dd></div><div><dt>Licence</dt><dd>${esc(page.meta.licence || 'CC BY 4.0')}</dd></div><div><dt>Steward</dt><dd>Kermani Kolankeh, Arash</dd></div><div><dt>URL</dt><dd>${esc(abs(page.path))}</dd></div></dl><p class="pc-note">This draft has not been reviewed by a standards body. It is not accreditation.</p></section>` : '';
  const ld = page.jsonld ? `<script type="application/ld+json">${JSON.stringify(page.jsonld)}</script>` : '';
  const canon = abs(page.path);
  const og = `<meta property="og:type" content="${page.path === '/' ? 'website' : 'article'}"><meta property="og:site_name" content="Sanad"><meta property="og:title" content="${esc(page.title)}"><meta property="og:description" content="${esc(page.description)}"><meta property="og:url" content="${canon}"><meta property="og:locale" content="${L.og}"><meta property="og:image" content="${abs('/assets/social-preview.png')}"><meta property="og:image:alt" content="Sanad: an open protocol for recomputable recognition of skills"><meta name="twitter:card" content="summary_large_image">`;
  return `<!doctype html>
<html lang="${lang}" dir="${L.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
<title>${esc(page.title)}${page.path === homePath ? '' : ' · Sanad'}</title>
<meta name="description" content="${esc(page.description)}">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#003B73">
<link rel="canonical" href="${canon}">
${hreflangs}
${og}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="alternate" type="application/atom+xml" title="Sanad news" href="/atom.xml">
<link rel="stylesheet" href="/assets/style.css">
${ld}
</head>
<body class="${page.template || 'doc'}${page.numbered ? ' numbered' : ''}">
<a class="skip" href="#main">${esc(t.skip)}</a>
<header class="site">
  <div class="wrap bar">
    <a class="brand" href="${homePath}" aria-label="Sanad, ${esc(t.home)}">${logoSvg('logo', 'Sanad')}</a>
    ${langSwitch(page, pagesByKey, lang)}
  </div>
  <div class="wrap">
    <nav class="primary" aria-label="${esc(t.menu)}"><ul>${nav}<li class="more"><details><summary>${esc(t.moreLabel)}</summary><ul>${more}</ul></details></li></ul></nav>
  </div>
  <div class="stamp"><div class="wrap"><span>${esc(t.stand)}: <time datetime="${SITE.stand}">${DATE_LONG[lang]}</time></span><span>${esc(page.stamp || (lang === 'en' ? 'Draft v0.1 · not accreditation' : lang === 'de' ? 'Entwurf v0.1 · keine Akkreditierung' : t.draft))}</span></div></div>
</header>
<div class="wrap">
${crumbs}
</div>
<main id="main" class="wrap">
${banner}
${cover}
<article>
<h1>${esc(page.h1 || page.title)}</h1>
${page.lead ? `<p class="lead">${page.lead}</p>` : ''}
${metaBlock}
${glance}
<div class="cols${toc ? ' hastoc' : ''}">
${toc}
<div class="body">
${page.html}
${page.footnotes || ''}
</div>
</div>
</article>
</main>
<footer class="site">
  <div class="wrap">
    <p class="fline">${esc(t.footerLine)}</p>
    <ul class="flinks">
      <li><a href="${lang === 'de' ? '/de/impressum/' : '/legal-notice/'}">${esc(t.footerLegal)}</a></li>
      <li><a href="${lang === 'de' ? '/de/datenschutz/' : '/privacy/'}">${esc(t.footerPrivacy)}</a></li>
      <li><a href="${lang === 'de' ? '/de/barrierefreiheit/' : '/accessibility/'}">${esc(t.footerAccess)}</a></li>
      <li><a href="${lang === 'de' ? '/de/kontakt/' : '/contact/'}">${esc(t.footerContact)}</a></li>
      <li><a href="${lang === 'de' ? '/de/lizenz/' : '/license/'}">${esc(t.footerLicence)}</a></li>
      <li><a href="/atom.xml">Atom</a></li>
    </ul>
    <p class="fsmall">sanadprotocol.org · ${esc(t.stand)} ${DATE_LONG[lang]} · <a href="#main">${esc(t.back)}</a></p>
  </div>
</footer>
</body>
</html>
`;
}
