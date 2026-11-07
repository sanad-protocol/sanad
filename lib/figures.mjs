// Three original figures of the specification, as inline SVG that follows the colour scheme of the page.
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const head = (id, w, h, title, desc) => `<svg viewBox="0 0 ${w} ${h}" role="img" aria-labelledby="${id}-t ${id}-d" focusable="false"><title id="${id}-t">${esc(title)}</title><desc id="${id}-d">${esc(desc)}</desc><defs><marker id="${id}-a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" class="i-arrowhead"/></marker></defs>`;
const box = (x, y, w, h, title, lines, cls = '') => `<g><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="4" class="i-card ${cls}"/><text x="${x + 12}" y="${y + 21}" class="i-label">${esc(title)}</text>${lines.map((t, k) => `<text x="${x + 12}" y="${y + 42 + k * 18}" class="i-text sm">${esc(t)}</text>`).join('')}</g>`;
const arrow = (id, d, dashed = false) => `<path d="${d}" class="i-line${dashed ? ' dashed' : ''}" marker-end="url(#${id}-a)"/>`;

export function figureDataModel() {
  const id = 'f1';
  return head(id, 900, 330, 'Figure 1: the Sanad data model', 'A claim refers to a skill of the concept graph and is backed by evidence of four kinds. Attestations are signed statements about evidence. A bundle hash covers the tree. A verifier policy and the credential are the inputs of the recognition function, which returns a result.') +
    box(0, 120, 170, 90, 'SKILL', ['node of the concept graph', 'id, prerequisites, graph hash']) +
    box(220, 120, 170, 90, 'CLAIM', ['subject (pseudonymous)', 'skill, level 0 to 5, date']) +
    box(440, 20, 190, 140, 'EVIDENCE', ['auto: replayable runs', 'sitting: live, hash chain', 'artifact: reviewed work', 'peer: peer review']) +
    box(440, 190, 190, 120, 'ATTESTATION', ['attestor (identifier)', 'level, role, conflict flag', 'commit, reveal, signature']) +
    box(680, 120, 220, 90, 'CREDENTIAL', ['claim + evidence + attestations', 'bundle hash (tree root)'], 'strong') +
    arrow(id, 'M170 165 H220') + arrow(id, 'M390 150 C415 150 415 90 440 90') + arrow(id, 'M630 250 C655 250 655 190 680 190') + arrow(id, 'M630 90 C655 90 655 140 680 140') +
    `<path d="M535 160 V190" class="i-line" marker-end="url(#${id}-a)"/><text x="545" y="180" class="i-tiny">about</text><text x="225" y="108" class="i-tiny">states</text><text x="400" y="104" class="i-tiny">backed by</text></svg>`;
}

export function figurePipeline() {
  const id = 'f2'; const steps = [['R1', 'integrity', 'hashes, reveals, chain'], ['R2', 'admissibility', 'conflicts, history, age'], ['R3', 'age factor', 'half-life of evidence'], ['R4', 'evidence level', 'lower median, capped by kind'], ['R5', 'independence', 'attestors, live sitting'], ['R6', 'recognised level', 'min of claim and evidence'], ['R7', 'confidence', '1 minus product of doubts'], ['R8', 'inference', 'prerequisite skills, flagged']];
  const cells = steps.map(([r, t, d], i) => { const x = 20 + (i % 4) * 215, y = i < 4 ? 70 : 215; return `<g><rect x="${x}" y="${y}" width="195" height="92" rx="4" class="i-card"/><text x="${x + 12}" y="${y + 24}" class="i-label">${r}</text><text x="${x + 12}" y="${y + 48}" class="i-text">${esc(t)}</text><text x="${x + 12}" y="${y + 70}" class="i-tiny">${esc(d)}</text></g>`; }).join('');
  return head(id, 900, 340, 'Figure 2: the recognition function', 'The credential and the verifier policy pass through the rules R1 to R8 in order. The output is a status, a level, a confidence, an ordered explanation and inferred skills.') +
    `<text x="20" y="34" class="i-label">INPUT</text><text x="70" y="34" class="i-text sm">credential (claim, evidence, attestations) and verifier policy</text>` + cells +
    arrow(id, 'M215 116 H235') + arrow(id, 'M430 116 H450') + arrow(id, 'M645 116 H665') + arrow(id, 'M757 162 V190 H117 V215') + arrow(id, 'M215 261 H235') + arrow(id, 'M430 261 H450') + arrow(id, 'M645 261 H665') +
    `<text x="20" y="328" class="i-label">OUTPUT</text><text x="82" y="328" class="i-text sm">status · level · confidence · ordered explanation · inferred skills (never published without the holder's choice)</text></svg>`;
}

export function figureLog() {
  const id = 'f3';
  const leaf = (x, t, on) => `<g><rect x="${x}" y="230" width="86" height="44" rx="3" class="i-card${on ? ' strong' : ''}"/><text x="${x + 43}" y="249" text-anchor="middle" class="i-tiny">attestation</text><text x="${x + 43}" y="265" text-anchor="middle" class="i-text sm">${t}</text></g>`;
  const node = (x, y, t, on) => `<g><rect x="${x}" y="${y}" width="86" height="34" rx="3" class="i-card${on ? ' strong' : ''}"/><text x="${x + 43}" y="${y + 22}" text-anchor="middle" class="i-text sm">${t}</text></g>`;
  return head(id, 900, 330, 'Figure 3: the transparency log', 'Hashes of attestations are the leaves of an append-only Merkle tree. The root is published in a signed checkpoint that may be timestamped. An inclusion proof consists of the sibling hashes on the path from one leaf to the root.') +
    leaf(10, 'h1', false) + leaf(106, 'h2', true) + leaf(202, 'h3', false) + leaf(298, 'h4', false) +
    node(58, 150, 'h(h1,h2)', true) + node(250, 150, 'h(h3,h4)', false) + node(154, 70, 'root', true) +
    arrow(id, 'M53 230 V190 H101 V184', false).replace('marker-end="url(#f3-a)"', '') + `<path d="M149 230 V190 H101 V184 M245 230 V190 H293 V184 M341 230 V190 H293 V184 M101 150 V110 H197 V104 M293 150 V110 H197 V104" class="i-line"/>` +
    `<g><rect x="470" y="40" width="250" height="150" rx="4" class="i-card strong"/><text x="484" y="64" class="i-label">SIGNED CHECKPOINT</text><text x="484" y="92" class="i-text sm">tree size</text><text x="484" y="112" class="i-text sm">root hash</text><text x="484" y="132" class="i-text sm">time</text><text x="484" y="152" class="i-text sm">signature of the log operator</text><text x="484" y="176" class="i-tiny">published daily</text></g>` +
    arrow(id, 'M240 87 H470') + `<g><rect x="760" y="70" width="130" height="90" rx="4" class="i-policy"/><text x="772" y="94" class="i-label">OPTIONAL</text><text x="772" y="116" class="i-text sm">public timestamp</text><text x="772" y="136" class="i-text sm">of the root</text></g>` + arrow(id, 'M720 115 H760', true) +
    `<text x="470" y="236" class="i-label">INCLUSION PROOF</text><text x="470" y="258" class="i-text sm">sibling hashes h1 and h(h3,h4) lead from the leaf h2 to the root.</text><text x="470" y="280" class="i-text sm">Consistency proofs show that the log was only appended to.</text><text x="470" y="302" class="i-tiny">The log contains hashes only, never content or names.</text></svg>`;
}
export const FIGURES = [
  { n: 1, id: 'fig-data-model', after: /^3\./, svg: figureDataModel, caption: '<strong>Figure 1.</strong> The data model of section 3: a claim about a skill is backed by typed evidence; attestations are signed statements about evidence; the credential carries a bundle hash over the whole tree.' },
  { n: 2, id: 'fig-recognition', after: /^5\./, svg: figurePipeline, caption: '<strong>Figure 2.</strong> The recognition function of section 5: rules R1 to R8 are applied in this order to the credential under the verifier\'s policy.' },
  { n: 3, id: 'fig-log', after: /^8\./, svg: figureLog, caption: '<strong>Figure 3.</strong> The transparency log of section 8: attestation hashes form an append-only Merkle tree; its root is published in a signed checkpoint.' },
];
