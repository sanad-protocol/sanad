// Hand-written inline SVG diagrams in two colours (ink and one accent), in English and German.
// All colours come from CSS classes (assets/style.css, section "diagrams"); there are no colour values in the markup.
// Motion is CSS only: classes .dr (stroke draw-in), .fi (fade), .tok (token), s1..s9 (sequence). Without animation the final state is shown.
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const text = (x, y, cls, s, extra = '') => `<text x="${x}" y="${y}" class="${cls}"${extra}>${esc(s)}</text>`;
const lines = (x, y, cls, arr, dy = 17, extra = '') => arr.map((s, k) => text(x, y + k * dy, cls, s, extra)).join('');
/** A line that draws itself in: pathLength 1 so one dash pattern fits every length. */
const line = (d, seq, cls = '') => `<path d="${d}" pathLength="1" class="ln dr s${seq} ${cls}"/>`;
const chev = (x, y, dir, seq, cls = '') => {
  const p = { down: `M${x - 5} ${y - 7}L${x} ${y}L${x + 5} ${y - 7}`, right: `M${x - 7} ${y - 5}L${x} ${y}L${x - 7} ${y + 5}`, left: `M${x + 7} ${y - 5}L${x} ${y}L${x + 7} ${y + 5}` }[dir];
  return `<path d="${p}" class="ln fi s${seq} ${cls}"/>`;
};

function wrap(id, w, h, title, desc, body, caption) {
  return `<figure class="dg" id="dg-${id}" data-diagram="${id}"><svg viewBox="0 0 ${w} ${h}" role="img" aria-labelledby="${id}-t ${id}-d" focusable="false"><title id="${id}-t">${esc(title)}</title><desc id="${id}-d">${esc(desc)}</desc>${body}</svg><figcaption>${esc(caption)}</figcaption></figure>`;
}

const COPY = {
  en: {
    actors: {
      title: 'The four actors of Sanad', cap: 'Who does what: learner, examiner, verifier and log operator.',
      desc: 'Four actors in a square. The learner keeps claims and evidence and passes evidence to the examiner. The examiner signs attestations and the hashes of the attestations go to the log operator, who keeps an append-only log. The learner passes the bundle to the verifier. The verifier recomputes the result under its own policy and asks the log for an inclusion proof.',
      items: [['Learner', ['keeps claims and', 'evidence; chooses what', 'is disclosed']], ['Examiner', ['signs what was seen;', 'declares conflicts', 'of interest']], ['Verifier', ['recomputes the result', 'under its own policy']], ['Log operator', ['keeps an append-only', 'log and publishes', 'checkpoints']]],
      edges: [['evidence'], ['attestation', 'hashes'], ['bundle'], ['inclusion', 'proof']],
    },
    chain: {
      title: 'From claim to record', cap: 'The chain: claim, evidence, commitment, blind marks, record.',
      desc: 'Five steps in a vertical chain. First a claim: a subject states a skill at a level. Second, evidence backs the claim. Third, each attestor publishes a commitment to a mark. Fourth, the marks are revealed only after all commitments are in, and are signed. Fifth, the hashes of the attestations are appended to the log as the record.',
      steps: [['Claim', ['A subject states a skill', 'at a level.']], ['Evidence', ['Typed evidence backs', 'the claim.']], ['Commitment', ['Each attestor commits to', 'a mark before any is shown.']], ['Blind marks', ['Revealed only after all', 'commitments are in; signed.']], ['Record', ['Attestation hashes are', 'appended to the log.']]],
    },
    verify: {
      title: 'How anyone verifies a record', cap: 'Verification is recomputation: no permission and no issuer are needed.',
      desc: 'Fetch the record. Recompute its hash. Compare it with the hash in the log, using an inclusion proof against a signed checkpoint. If both are equal, run the recognition function under your own policy. The result is a status, a level, a confidence and an ordered explanation. Hash values shown are examples.',
      rec: ['Record', 'claim, evidence, attestations'], recompute: 'recompute the hash', hA: 'Computed hash', hB: 'Hash in the log', equal: 'equal', run: ['Run the recognition', 'function under your own policy'], out: ['Result', 'status, level, confidence, explanation'],
    },
    tamper: {
      title: 'A tampered record is rejected', cap: 'Change one mark and the hashes differ: the item is dropped and the reason is recorded.',
      desc: 'A record in which one mark was changed is fetched. The recomputed hash differs from the hash in the log. Rule R1, integrity, drops the item and records the reason. The result is recomputed without the dropped item. Hash values shown are examples.',
      rec: ['Record', 'one mark was changed'], recompute: 'recompute the hash', hA: 'Computed hash', hB: 'Hash in the log', equal: 'different', run: ['Rule R1 (integrity)', 'drops the item, records why'], out: ['Result', 'recomputed without it'],
    },
  },
  de: {
    actors: {
      title: 'Die vier Beteiligten bei Sanad', cap: 'Wer was tut: Lernende, Bestätigende, prüfende Stelle und Protokollbetreiber.',
      desc: 'Vier Beteiligte in einem Quadrat. Die Lernenden halten Behauptungen und Nachweise und geben Nachweise an die Bestätigenden. Die Bestätigenden signieren; die Hashes der Bestätigungen gehen an den Protokollbetreiber, der ein nur anfügbares Protokoll führt. Die Lernenden geben das Bündel an die prüfende Stelle. Diese berechnet das Ergebnis nach eigener Richtlinie neu und verlangt vom Protokoll einen Inklusionsbeweis.',
      items: [['Lernende', ['halten Behauptungen und', 'Nachweise, bestimmen', 'die Offenlegung']], ['Bestätigende', ['signieren, was sie', 'gesehen haben; legen', 'Konflikte offen']], ['Prüfende Stelle', ['rechnet das Ergebnis', 'nach eigener', 'Richtlinie nach']], ['Protokollbetreiber', ['betreibt das Protokoll', 'und veröffentlicht', 'Checkpoints']]],
      edges: [['Nachweis'], ['Hashes der', 'Bestätigungen'], ['Bündel'], ['Inklusions-', 'beweis']],
    },
    chain: {
      title: 'Von der Behauptung zum Eintrag', cap: 'Die Kette: Behauptung, Nachweis, Festlegung, verdeckte Bewertung, Eintrag.',
      desc: 'Fünf Schritte in einer senkrechten Kette. Erstens eine Behauptung: eine Person erklärt eine Fähigkeit auf einem Niveau. Zweitens stützt ein Nachweis die Behauptung. Drittens veröffentlicht jede bestätigende Person eine Festlegung auf eine Bewertung. Viertens werden die Bewertungen erst offengelegt, wenn alle Festlegungen vorliegen, und signiert. Fünftens werden die Hashes der Bestätigungen dem Protokoll als Eintrag angefügt.',
      steps: [['Behauptung', ['Eine Person erklärt eine', 'Fähigkeit auf einem Niveau.']], ['Nachweis', ['Nachweise verschiedener', 'Art stützen sie.']], ['Festlegung', ['Jede bestätigende Person', 'legt ihre Bewertung fest.']], ['Verdeckte Bewertung', ['Offengelegt erst, wenn alle', 'Festlegungen da sind; signiert.']], ['Eintrag', ['Die Hashes der Bestätigungen', 'werden dem Protokoll angefügt.']]],
    },
    verify: {
      title: 'Wie jede Person einen Eintrag prüft', cap: 'Prüfen heißt nachrechnen: weder Erlaubnis noch Aussteller sind nötig.',
      desc: 'Den Eintrag abrufen. Seinen Hash neu berechnen. Mit dem Hash im Protokoll vergleichen, über einen Inklusionsbeweis gegen einen signierten Checkpoint. Sind beide gleich, die Anerkennungsfunktion nach eigener Richtlinie ausführen. Das Ergebnis besteht aus Status, Niveau, Verlässlichkeit und einer geordneten Begründung. Die gezeigten Hashwerte sind Beispiele.',
      rec: ['Eintrag', 'Behauptung, Nachweise, Bestätigungen'], recompute: 'Hash neu berechnen', hA: 'Berechneter Hash', hB: 'Hash im Protokoll', equal: 'gleich', run: ['Anerkennungsfunktion', 'nach eigener Richtlinie ausführen'], out: ['Ergebnis', 'Status, Niveau, Verlässlichkeit, Begründung'],
    },
    tamper: {
      title: 'Ein manipulierter Eintrag wird abgelehnt', cap: 'Wird eine Bewertung geändert, weichen die Hashes ab: das Element entfällt, der Grund wird festgehalten.',
      desc: 'Ein Eintrag, in dem eine Bewertung geändert wurde, wird abgerufen. Der neu berechnete Hash weicht vom Hash im Protokoll ab. Regel R1, Integrität, verwirft das Element und hält den Grund fest. Das Ergebnis wird ohne das verworfene Element neu berechnet. Die gezeigten Hashwerte sind Beispiele.',
      rec: ['Eintrag', 'eine Bewertung wurde geändert'], recompute: 'Hash neu berechnen', hA: 'Berechneter Hash', hB: 'Hash im Protokoll', equal: 'verschieden', run: ['Regel R1 (Integrität)', 'verwirft es, hält den Grund fest'], out: ['Ergebnis', 'ohne das Element neu berechnet'],
    },
  },
};

function actors(lang) {
  const c = COPY[lang].actors; const W = 164, H = 118; const pos = [[0, 0], [236, 0], [0, 192], [236, 192]];
  // order of the items: learner, examiner, verifier, log operator
  const box = (i, seq) => { const [x, y] = pos[i]; const [t, ls] = c.items[i]; const acc = i === 3 ? ' a' : '';
    return `<g class="fi s${seq}"><rect x="${x}" y="${y}" width="${W}" height="${H}" class="box${acc}"/>${text(x + 14, y + 28, 'h', t)}${lines(x + 14, y + 52, 'sub', ls, 18)}</g>`; };
  const [eEv, eAt, eBu, ePr] = c.edges;
  const body = box(0, 1) + box(1, 2) + box(3, 4) + box(2, 6) +
    line('M164 59H228', 2) + chev(228, 59, 'right', 2) + text(200, 50, 'lab mid', eEv[0]) +
    line('M318 118V184', 3) + chev(318, 184, 'down', 3) + lines(326, 148, 'lab', eAt, 14) +
    line('M82 118V184', 5, 'accent') + chev(82, 184, 'down', 5, 'accent') + lines(90, 154, 'lab', eBu, 14) +
    line('M236 251H172', 6, 'accent') + chev(172, 251, 'left', 6, 'accent') + lines(200, 224, 'lab mid', ePr, 13);
  return wrap('actors', 400, 310, c.title, c.desc, body, c.cap);
}

function chain(lang) {
  const c = COPY[lang].chain; const X = 24; const Y0 = 22; const STEP = 84;
  let body = '';
  c.steps.forEach(([t, ls], i) => {
    const ty = Y0 + i * STEP; const last = i === c.steps.length - 1; const seq = i + 1;
    if (!last) body += line(`M${X} ${ty + 36}V${ty + STEP + 14}`, seq);
    body += `<g class="fi s${seq}"><rect x="${X - 11}" y="${ty + 14}" width="22" height="22" class="box${last ? ' solid' : ''}"/>${text(56, ty + 12, 'tag', String(i + 1).padStart(2, '0'))}${text(56, ty + 32, 'h', t)}${lines(56, ty + 51, 'sub', ls, 17)}</g>`;
  });
  const endY = Y0 + 4 * STEP + 25;
  body += `<circle cx="${X}" cy="${endY}" r="4.5" class="tok tokchain"/>`;
  return wrap('chain', 400, Y0 + 4 * STEP + 90, c.title, c.desc, body, c.cap);
}

function pair(id, lang, mismatch) {
  const c = COPY[lang][id]; const A = mismatch ? 'e7d0 51b8 2c9a' : 'a41f 09c2 7be3'; const B = 'a41f 09c2 7be3';
  const body =
    `<g class="fi s1"><rect x="0" y="0" width="400" height="66" class="box${mismatch ? ' a' : ''}"/>${text(16, 28, 'h', c.rec[0])}${text(16, 50, 'sub', c.rec[1])}</g>` +
    line('M200 66V112', 2) + chev(200, 112, 'down', 2) + text(212, 94, 'lab', c.recompute) +
    `<g class="fi s3"><rect x="0" y="120" width="164" height="76" class="box${mismatch ? ' a' : ''}"/>${text(14, 144, 'sub', c.hA)}${text(14, 172, `mono${mismatch ? ' acc' : ''}`, A)}</g>` +
    `<g class="fi s3"><rect x="236" y="120" width="164" height="76" class="box"/>${text(250, 144, 'sub', c.hB)}${text(250, 172, 'mono', B)}</g>` +
    (mismatch
      ? line('M184 148L216 168M216 148L184 168', 4, 'accent thick')
      : line('M184 159L194 169L216 147', 4, 'accent thick')) +
    text(200, 190, 'lab mid acc', c.equal) +
    line('M200 200V244', 5, 'accent') + chev(200, 244, 'down', 5, 'accent') +
    `<g class="fi s6"><rect x="0" y="252" width="400" height="66" class="box a"/>${text(16, 280, 'h', c.run[0])}${text(16, 302, 'sub', c.run[1])}</g>` +
    line('M200 318V352', 7) + chev(200, 352, 'down', 7) +
    `<g class="fi s8"><rect x="0" y="360" width="400" height="60" class="box${mismatch ? '' : ' solid'}"/>${text(16, 386, `h${mismatch ? '' : ' on'}`, c.out[0])}${text(16, 406, `sub${mismatch ? '' : ' on'}`, c.out[1])}</g>`;
  return wrap(id, 400, 426, c.title, c.desc, body, c.cap);
}

const MAKERS = { actors, chain, verify: (l) => pair('verify', l, false), tamper: (l) => pair('tamper', l, true) };
export const DIAGRAM_NAMES = Object.keys(MAKERS);
export const diagram = (name, lang) => { if (!MAKERS[name]) throw new Error('unknown diagram ' + name); return MAKERS[name](lang === 'de' ? 'de' : 'en'); };
/** Replaces <!-- diagram:a,b --> in rendered markdown by a figure row. */
export const embedDiagrams = (html, lang) => html.replace(/<!-- diagram:([\w,-]+) -->/g, (_, names) => `<div class="dgrid">${names.split(',').map((n) => diagram(n, lang)).join('')}</div>`);
