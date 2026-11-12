// The home page, built from real data: the sample credential, the strict and the loose vector, the number of passing vectors and the news.
import { esc } from './layout.mjs';
import { DATE_LONG } from './i18n.mjs';
import { diagram } from './diagrams.mjs';

const REPO = 'https://github.com/sanad-protocol/sanad';
const COPY = {
  en: {
    eyebrow: 'Open protocol · v0.1', primary: 'Read the specification', secondary: 'Get the engine',
    badgeLicence: 'CC BY 4.0 text', badgeCode: 'Apache-2.0 code', badgeRef: 'Reference implementation', badgeVec: (n, m) => `${n}/${m} conformance vectors pass`,
    ill: { title: 'Schematic: data flow of the recognition function', desc: 'A claim, typed evidence and signed attestations are inputs of the recognition function. The verifier supplies a policy. The result consists of a status, a level, a confidence and an ordered explanation.', claim: 'CLAIM', claimLines: ['subject, skill, level', 'date, graph version'], evidence: 'EVIDENCE', evidenceLines: ['replayable practice runs', 'live sitting', 'reviewed work', 'peer review'], attest: 'ATTESTATIONS', attestLines: ['signed by attestors', 'blind marks, commit and reveal'], policy: 'VERIFIER POLICY', policyLine: 'set by the verifier', func: 'recognise()', rules: 'rules R1 to R8', result: 'RESULT', resultLines: ['status', 'level, confidence', 'ordered explanation'], cap: 'Schematic of the data flow (section 5 of the specification).' },
    glanceH: 'Specification at a glance', glanceSub: 'Document metadata of the current version.',
    facts: [['Document', 'SANAD-SPEC-0.1'], ['Version', '0.1'], ['Status', 'Open for comment'], ['Date', null], ['Licence', 'Text CC BY 4.0 · code Apache-2.0'], ['Steward and editor', 'Kermani Kolankeh, Arash'], ['Repository', REPO], ['Formats', 'HTML · PDF (tagged)']],
    dgH: 'The chain at a glance', dgSub: 'Who takes part, how a record comes about, and how anyone can check it.', dgV: 'Checking a record', dgVSub: 'Verification is recomputation. A changed record is detected, not trusted.',
    howH: 'How it works', howSub: 'From a claim to a result that any verifier can recompute.',
    steps: [['Claim', 'A subject states a skill at a level. The skill is a node in an open, versioned concept graph.'], ['Evidence', 'Typed evidence backs the claim: replayable practice runs, a live sitting, reviewed work, peer review.'], ['Attestation', 'Attestors sign what they saw. Marks are committed blind before any is revealed, so they are independent of one another.'], ['Recognition', 'A verifier runs the published function under its own policy and obtains a status, a level, a confidence and an ordered explanation.']],
    whoH: 'Who it is for',
    who: [['Learners', 'Holding claims and evidence; choosing what is published.', '/for/learners/'], ['Examiners and assessors', 'Signing attestations; declaring conflicts of interest.', '/for/examiners/'], ['Universities and employers', 'Defining a policy and running the recognition function.', '/for/institutions/'], ['Implementers', 'Building verifiers, issuers, attestors, logs and indexes.', '/for/implementers/'], ['Funders', 'Costs, twelve-month plan and risk register.', '/for/funders/'], ['Press', 'Fact sheet and contacts.', '/for/press/']],
    latestH: 'Latest', latestAll: 'All news',
    involveH: 'Get involved', involveP: 'Sanad is maintained by one steward; a second steward is being appointed. Reviews, independent implementations and written criticism are the contributions needed at this stage.',
    involve: [['Review the specification', 'Read the specification and comment on any section.', '/spec/0.1/'], ['Run the vectors', 'Run the reference verifier or your own implementation.', '/conformance/'], ['Join the discussion', 'How decisions are made and how to take part.', '/participate/'], ['Report an issue', 'Open an issue in the repository.', REPO + '/issues']],
    statusH: 'Status', status: 'Sanad (v0.1) uses **decentralised assessment**: it does not accredit anyone and does not decide what a verifier must accept. It has **no token** and no financial component.',
    pdf: '/spec/SANAD-SPEC-0.1.pdf',
  },
  de: {
    eyebrow: 'Offenes Protokoll · v0.1', primary: 'Spezifikation lesen', secondary: 'Engine holen',
    badgeLicence: 'Text CC BY 4.0', badgeCode: 'Code Apache-2.0', badgeRef: 'Referenzimplementierung', badgeVec: (n, m) => `${n}/${m} Konformitätsvektoren bestanden`,
    ill: { title: 'Schema: Datenfluss der Anerkennungsfunktion', desc: 'Eine Behauptung, Nachweise verschiedener Art und signierte Bestätigungen sind Eingaben der Anerkennungsfunktion. Die prüfende Stelle liefert eine Richtlinie. Das Ergebnis besteht aus Status, Niveau, Verlässlichkeit und einer geordneten Begründung.', claim: 'BEHAUPTUNG', claimLines: ['Person, Fähigkeit, Niveau', 'Datum, Graphversion'], evidence: 'NACHWEISE', evidenceLines: ['wiederholbare Übungsläufe', 'Präsenzsitzung', 'begutachtete Arbeit', 'gegenseitige Begutachtung'], attest: 'BESTÄTIGUNGEN', attestLines: ['von Bestätigenden signiert', 'verdeckte Bewertung (Commit, Reveal)'], policy: 'RICHTLINIE', policyLine: 'von der prüfenden Stelle', func: 'recognise()', rules: 'Regeln R1 bis R8', result: 'ERGEBNIS', resultLines: ['Status', 'Niveau, Verlässlichkeit', 'geordnete Begründung'], cap: 'Schema des Datenflusses (Abschnitt 5 der Spezifikation).' },
    glanceH: 'Spezifikation auf einen Blick', glanceSub: 'Metadaten der aktuellen Version.',
    facts: [['Dokument', 'SANAD-SPEC-0.1'], ['Version', '0.1'], ['Status', 'Offen für Anmerkungen'], ['Datum', null], ['Lizenz', 'Text CC BY 4.0 · Code Apache-2.0'], ['Verantwortlich und Redaktion', 'Kermani Kolankeh, Arash'], ['Repository', REPO], ['Formate', 'HTML · PDF (barrierearm ausgezeichnet)']],
    dgH: 'Die Kette auf einen Blick', dgSub: 'Wer beteiligt ist, wie ein Eintrag entsteht und wie ihn jede Person prüfen kann.', dgV: 'Einen Eintrag prüfen', dgVSub: 'Prüfen heißt nachrechnen. Ein veränderter Eintrag wird erkannt, nicht geglaubt.',
    howH: 'So funktioniert es', howSub: 'Von der Behauptung zu einem Ergebnis, das jede prüfende Stelle nachrechnen kann.',
    steps: [['Behauptung', 'Eine Person erklärt eine Fähigkeit auf einem Niveau. Die Fähigkeit ist ein Knoten in einem offenen, versionierten Begriffsgraphen.'], ['Nachweis', 'Nachweise verschiedener Art stützen die Behauptung: wiederholbare Übungsläufe, eine Präsenzsitzung, begutachtete Arbeiten, gegenseitige Begutachtung.'], ['Bestätigung', 'Bestätigende signieren, was sie gesehen haben. Bewertungen werden zuvor verdeckt festgelegt und erst danach offengelegt, sodass sie unabhängig bleiben.'], ['Anerkennung', 'Eine prüfende Stelle führt die veröffentlichte Funktion mit ihrer eigenen Richtlinie aus und erhält Status, Niveau, Verlässlichkeit und eine geordnete Begründung.']],
    whoH: 'Für wen',
    who: [['Lernende', 'Behauptungen und Nachweise halten; entscheiden, was veröffentlicht wird.', '/for/learners/'], ['Prüfende und Bestätigende', 'Bestätigungen signieren; Interessenkonflikte offenlegen.', '/for/examiners/'], ['Hochschulen und Unternehmen', 'Eine Richtlinie festlegen und die Anerkennungsfunktion ausführen.', '/for/institutions/'], ['Entwickelnde', 'Prüfer, Aussteller, Bestätigungswerkzeuge, Protokolle und Indizes bauen.', '/for/implementers/'], ['Förderer', 'Kosten, Zwölfmonatsplan und Risikoregister.', '/for/funders/'], ['Presse', 'Datenblatt und Kontakte.', '/for/press/']],
    latestH: 'Neuigkeiten', latestAll: 'Alle Neuigkeiten',
    involveH: 'Mitmachen', involveP: 'Sanad wird von einer verantwortlichen Person betreut; eine zweite wird gewonnen. In dieser Phase werden Prüfungen, unabhängige Implementierungen und schriftliche Kritik benötigt.',
    involve: [['Spezifikation prüfen', 'Lesen Sie die Spezifikation und kommentieren Sie jeden Abschnitt.', '/spec/0.1/'], ['Vektoren ausführen', 'Führen Sie den Referenzprüfer oder Ihre eigene Implementierung aus.', '/conformance/'], ['Mitdiskutieren', 'Wie Entscheidungen fallen und wie Sie sich beteiligen.', '/de/mitmachen/'], ['Problem melden', 'Eröffnen Sie einen Beitrag im Repository.', REPO + '/issues']],
    statusH: 'Status', status: 'Sanad (Version 0.1) beruht auf **dezentraler Bewertung**: Es akkreditiert niemanden und bestimmt nicht, was eine prüfende Stelle akzeptieren muss. Es gibt **kein Token** und keine finanzielle Komponente.',
    pdf: '/spec/SANAD-SPEC-0.1.pdf',
  },
};

const ICON = {
  claim: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 12h6M9 16h4"/></svg>',
  evidence: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 3 8l9 5 9-5z"/><path d="m3 13 9 5 9-5"/><path d="m3 17.5 9 5 9-5" opacity=".55"/></svg>',
  attest: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="m9 12 2.2 2.2L15.5 10"/></svg>',
  recog: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/><circle cx="12" cy="18" r="1.2" fill="currentColor"/><path d="M5.5 9.5 7 11M12 6v2M18.5 9.5 17 11" opacity=".6"/></svg>',
};

function illustration(c) {
  const I = c.ill;
  const box = (x, y, w, h, label, lines) => `<g><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="4" class="i-card"/><text x="${x + 14}" y="${y + 24}" class="i-label">${esc(label)}</text>${lines.map((t, k) => `<text x="${x + 14}" y="${y + 48 + k * 20}" class="i-text">${esc(t)}</text>`).join('')}</g>`;
  return `<svg viewBox="0 0 660 360" role="img" aria-labelledby="ill-t ill-d" focusable="false"><title id="ill-t">${esc(I.title)}</title><desc id="ill-d">${esc(I.desc)}</desc>
<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" class="i-arrowhead"/></marker></defs>
${box(0, 0, 232, 96, I.claim, I.claimLines)}${box(0, 120, 232, 112, I.evidence, I.evidenceLines)}${box(0, 256, 232, 96, I.attest, I.attestLines)}
<path d="M232 48 C292 48 292 150 328 162" class="i-line" marker-end="url(#arr)"/><path d="M232 176 H328" class="i-line" marker-end="url(#arr)"/><path d="M232 304 C292 304 292 202 328 190" class="i-line" marker-end="url(#arr)"/>
<g><rect x="262" y="22" width="168" height="48" rx="24" class="i-policy"/><text x="346" y="42" text-anchor="middle" class="i-label">${esc(I.policy)}</text><text x="346" y="59" text-anchor="middle" class="i-tiny2">${esc(I.policyLine)}</text><path d="M346 70V118" class="i-line dashed" marker-end="url(#arr)"/></g>
<g><rect x="328" y="120" width="120" height="112" rx="4" class="i-func"/><text x="388" y="172" text-anchor="middle" class="i-funcT">${esc(I.func)}</text><text x="388" y="194" text-anchor="middle" class="i-funcS">${esc(I.rules)}</text></g>
<path d="M448 176 H472" class="i-line" marker-end="url(#arr)"/>
${box(472, 112, 188, 128, I.result, I.resultLines)}
</svg>`;
}

export function homeHtml(lang, d) {
  const c = COPY[lang]; const dateLong = DATE_LONG[lang];
  const pass = d.vectors.filter((v) => v.ok).length, total = d.vectors.length;
  const md = (s) => s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  const facts = c.facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${k === c.facts[3][0] ? `<time datetime="2026-11-07">${esc(dateLong)}</time>` : /^https:/.test(v) ? `<a href="${v}" rel="noopener" class="ext">github.com/sanad-protocol/sanad</a>` : k === c.facts[7][0] ? `<a href="/spec/0.1/">HTML</a> · <a href="${c.pdf}">PDF</a>` : esc(v)}</dd></div>`).join('');
  const hero = `<section class="hero"><div class="wrap grid"><div><p class="eyebrow">${esc(c.eyebrow)}</p><h1>${esc(d.h1)}</h1><p class="lead">${esc(d.lead)}</p>
<ul class="cta"><li><a class="btn primary" href="/spec/0.1/">${esc(c.primary)}</a></li><li><a class="btn" href="${lang === 'de' ? '/de/engine/' : '/engine/'}">${esc(c.secondary)}</a></li></ul>
<ul class="badges"><li><span class="badge draft">${esc(lang === 'de' ? 'v0.1' : 'v0.1')}</span></li><li><span class="badge plain">${esc(c.badgeLicence)}</span></li><li><span class="badge plain">${esc(c.badgeCode)}</span></li><li><span class="badge ${pass === total ? 'ok' : 'draft'}">${esc(c.badgeVec(pass, total))}</span></li><li><a class="badge plain" href="${REPO}/tree/main/reference">${esc(c.badgeRef)}</a></li></ul></div>
<figure>${illustration(c, d)}<figcaption>${esc(c.ill.cap)}</figcaption></figure></div></section>`;
  const glance = `<section class="band" aria-labelledby="gl-h"><div class="wrap"><div class="sechead"><h2 id="gl-h">${esc(c.glanceH)}</h2><p>${esc(c.glanceSub)}</p></div><dl class="glancegrid">${facts}</dl></div></section>`;
  const how = `<section class="band alt" aria-labelledby="how-h"><div class="wrap"><div class="sechead"><h2 id="how-h">${esc(c.howH)}</h2><p>${esc(c.howSub)}</p></div><ol class="steps">${c.steps.map(([h, p], i) => `<li>${[ICON.claim, ICON.evidence, ICON.attest, ICON.recog][i]}<strong>${esc(h)}</strong><p>${esc(p)}</p></li>`).join('')}</ol></div></section>`;
  const dg = `<section class="band" aria-labelledby="dg-h"><div class="wrap"><div class="sechead"><h2 id="dg-h">${esc(c.dgH)}</h2><p>${esc(c.dgSub)}</p></div><div class="dgrid">${diagram('actors', lang)}${diagram('chain', lang)}</div></div></section><section class="band" aria-labelledby="dgv-h"><div class="wrap"><div class="sechead"><h2 id="dgv-h">${esc(c.dgV)}</h2><p>${esc(c.dgVSub)}</p></div><div class="dgrid">${diagram('verify', lang)}${diagram('tamper', lang)}</div></div></section>`;
  const who = `<section class="band alt" aria-labelledby="who-h"><div class="wrap"><div class="sechead"><h2 id="who-h">${esc(c.whoH)}</h2></div><div class="cards linked">${c.who.map(([h, p, href]) => `<div><h3><a href="${href}">${esc(h)}<span class="arrow" aria-hidden="true">→</span></a></h3><p>${esc(p)}</p></div>`).join('')}</div></div></section>`;
  const latest = `<section class="band" aria-labelledby="latest-h"><div class="wrap"><div class="sechead"><h2 id="latest-h">${esc(c.latestH)}</h2><p><a href="/news/">${esc(c.latestAll)}</a></p></div><ul class="latest">${d.news.slice(0, 3).map((n) => `<li><time datetime="${n.date}">${esc(lang === 'de' ? new Date(n.date).toLocaleDateString('de-DE', { day: 'numeric', month: 'long', year: 'numeric' }) : new Date(n.date).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }))}</time><div><strong>${esc(n.title)}</strong><p>${esc(n.summary)}</p></div></li>`).join('')}</ul></div></section>`;
  const involve = `<section class="band dark" aria-labelledby="inv-h"><div class="wrap"><div class="sechead"><h2 id="inv-h">${esc(c.involveH)}</h2><p>${esc(c.involveP)}</p></div><div class="involve">${c.involve.map(([h, p, href]) => `<a href="${href}"${/^https?:/.test(href) ? ' rel="noopener"' : ''}><strong>${esc(h)}</strong><span>${esc(p)}</span></a>`).join('')}</div></div></section>`;
  const status = `<section class="band" aria-labelledby="st-h"><div class="wrap"><div class="status-box"><h3 id="st-h">${esc(c.statusH)}</h3><p>${md(esc(c.status))}</p></div></div></section>`;
  return hero + glance + how + dg + who + latest + involve + status;
}
