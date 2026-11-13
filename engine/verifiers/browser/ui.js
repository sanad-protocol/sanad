// Page logic: reads a directory (folder picker) or a zip, collects the verifier's own choices and prints the report. Nothing leaves the page.
(function () {
  'use strict';
  if (typeof document === 'undefined') return;
  const $ = (id) => document.getElementById(id);
  const list = (v) => v.split(',').map((x) => x.trim()).filter(Boolean);
  let files = null;
  $('policy').value = JSON.stringify(SanadVerifier.DEFAULT_POLICY, null, 2);
  async function load(kind, input) {
    try {
      if (kind === 'zip') files = await SanadVerifier.readZip(await input.files[0].arrayBuffer());
      else { files = new Map(); for (const f of input.files) files.set(f.webkitRelativePath || f.name, await f.text()); }
      $('loaded').textContent = files.size + ' files loaded.';
    } catch (e) { files = null; $('loaded').textContent = 'Could not read it: ' + e.message; }
  }
  $('dir').addEventListener('change', (e) => load('dir', e.target));
  $('zip').addEventListener('change', (e) => load('zip', e.target));
  $('run').addEventListener('click', async () => {
    const res = $('result'); res.textContent = '';
    if (!files) { res.textContent = 'Choose a folder or a zip first.'; return; }
    let policy; try { policy = JSON.parse($('policy').value); } catch { res.textContent = 'The policy is not valid JSON.'; return; }
    const o = { policy, trustedIssuers: list($('issuer').value), trustedLogKeys: list($('logkey').value) };
    if ($('witnesses').value.trim()) { o.trustedWitnesses = list($('witnesses').value); o.requireWitnesses = Number($('nwit').value || 1); }
    if ($('minid').value) o.minIdentityLevel = $('minid').value;
    if ($('reqstatus').checked) o.requireStatus = true;
    if ($('pinned').value.trim()) { try { o.pinnedKeys = JSON.parse($('pinned').value); } catch { res.textContent = 'Pinned keys must be JSON like {"did:web:x": ["z..."]}.'; return; } }
    const r = await SanadVerifier.verifyTree(files, o);
    const frag = document.createDocumentFragment();
    const h = document.createElement('h2'); h.textContent = r.ok ? 'All checks passed' : 'Not verified'; h.className = r.ok ? 'ok' : 'bad'; frag.append(h);
    const ul = document.createElement('ul');
    for (const c of r.checks) { const li = document.createElement('li'); li.className = c.ok ? 'ok' : 'bad'; li.textContent = (c.ok ? 'PASS ' : 'FAIL ') + c.name + ': ' + c.detail; ul.append(li); }
    for (const w of r.warnings) { const li = document.createElement('li'); li.className = 'warn'; li.textContent = 'WARN ' + w; ul.append(li); }
    frag.append(ul);
    if (r.recognition) {
      const p = document.createElement('p');
      p.textContent = (r.ok ? '' : 'Unverified, this is what the data would give if it were genuine: ') + 'status ' + r.recognition.status + ', level ' + r.recognition.level + ', confidence ' + r.recognition.confidence + ' (your policy, evaluation day ' + r.recognition.policy.asOf + ')';
      frag.append(p);
      const ol = document.createElement('ol');
      for (const s of r.recognition.explanation) { const li = document.createElement('li'); li.textContent = s.rule + ' ' + s.summary; ol.append(li); }
      frag.append(ol);
    }
    const n = document.createElement('p'); n.className = 'note'; n.textContent = 'Experimental software: a passing report records what was signed and logged, not that the attestors were honest.'; frag.append(n);
    res.append(frag);
  });
})();
