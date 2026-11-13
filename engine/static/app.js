import { newAttestor, prepareCommit, prepareReveal } from './sanad-client.js';
const $ = (id) => document.getElementById(id);
const show = (el, v) => { el.textContent = typeof v === 'string' ? v : JSON.stringify(v, null, 2); };
async function api(method, path, body) {
  const r = await fetch(path, { method, headers: body === undefined ? {} : { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j.error ?? r.status) + ': ' + (j.message ?? r.statusText));
  return j;
}
let attestor = null;
const secrets = new Map(); // kept in memory only

api('GET', '/v1/info').then((i) => show($('info'), i), (e) => show($('info'), String(e.message)));

$('verify').addEventListener('click', async () => {
  const out = $('report'); out.textContent = '';
  try {
    const body = { credential: JSON.parse($('cred').value) };
    if ($('policy').value.trim()) body.policy = JSON.parse($('policy').value);
    const r = await api('POST', '/v1/verify', body);
    const head = document.createElement('p'); head.className = r.ok ? 'ok' : 'bad'; head.textContent = r.ok ? 'All checks passed' : 'Some checks failed'; out.append(head);
    const ul = document.createElement('ul');
    for (const c of r.checks) { const li = document.createElement('li'); li.textContent = (c.ok ? 'PASS ' : 'FAIL ') + c.name + ': ' + c.detail; li.className = c.ok ? 'ok' : 'bad'; ul.append(li); }
    out.append(ul);
    for (const w of r.warnings) { const p = document.createElement('p'); p.textContent = 'Warning: ' + w; out.append(p); }
    if (r.recognition) {
      const p = document.createElement('p');
      p.textContent = `Recognition (${body.policy ? 'your policy' : 'the template recommendation only'}): ${r.recognition.status}, level ${r.recognition.level}, confidence ${r.recognition.confidence}`;
      out.append(p);
    }
  } catch (e) { out.textContent = 'Error: ' + e.message; }
});

$('newkey').addEventListener('click', async () => { attestor = await newAttestor(); $('did').textContent = attestor.did; });
$('commit').addEventListener('click', async () => {
  try {
    if (!attestor) throw new Error('make a key first');
    const aid = $('aid').value.trim(), attId = $('attid').value.trim();
    const assessment = await api('GET', '/v1/assessments/' + encodeURIComponent(aid));
    const { request, secret } = await prepareCommit({ attestor, assessment, attestationId: attId, level: Number($('level').value) });
    secrets.set(aid + '/' + attId, secret);
    show($('attout'), await api('POST', '/v1/assessments/' + encodeURIComponent(aid) + '/commit', request));
  } catch (e) { show($('attout'), 'Error: ' + e.message); }
});
$('reveal').addEventListener('click', async () => {
  try {
    if (!attestor) throw new Error('make a key first');
    const aid = $('aid').value.trim(), attId = $('attid').value.trim();
    const secret = secrets.get(aid + '/' + attId);
    if (!secret) throw new Error('no commit made from this tab for ' + attId);
    const assessment = await api('GET', '/v1/assessments/' + encodeURIComponent(aid));
    const date = $('date').value.trim() || new Date().toISOString().slice(0, 10);
    show($('attout'), await api('POST', '/v1/assessments/' + encodeURIComponent(aid) + '/reveal', await prepareReveal({ attestor, assessment, attestationId: attId, secret, date })));
  } catch (e) { show($('attout'), 'Error: ' + e.message); }
});
