// Progressive enhancement only: copy buttons on code blocks and the contact form. The pages are fully readable without this file.
(function () {
  // diagrams: start the short animation when a figure scrolls into view; without this code (or with reduced motion) the final state is shown
  var dgs = document.querySelectorAll('figure.dg');
  if (dgs.length && 'IntersectionObserver' in window && !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) {
    var io = new IntersectionObserver(function (es) { es.forEach(function (e) { if (e.isIntersecting) { e.target.setAttribute('data-run', ''); io.unobserve(e.target); } }); }, { threshold: 0.35 });
    dgs.forEach(function (f) { f.setAttribute('data-armed', ''); io.observe(f); });
  }
  var canCopy = !!(navigator.clipboard && navigator.clipboard.writeText);
  if (canCopy) document.querySelectorAll('pre').forEach(function (pre) {
    var b = document.createElement('button'); b.type = 'button'; b.className = 'copy'; b.textContent = 'Copy'; b.setAttribute('aria-label', 'Copy this code to the clipboard');
    b.addEventListener('click', function () { var code = pre.querySelector('code'); navigator.clipboard.writeText((code || pre).innerText).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1800); }); });
    pre.appendChild(b);
  });
  var form = document.getElementById('mailform'); if (!form) return;
  var subj = document.getElementById('f-subj'), status = document.getElementById('f-status'), secnote = document.getElementById('f-secnote');
  var label = function (el) { return el.options[el.selectedIndex].text; };
  function sync() { secnote.hidden = subj.value !== 'security'; } sync(); subj.addEventListener('change', sync);
  var send = document.getElementById('f-send');
  var say = function (key) { status.textContent = form.getAttribute('data-' + key); };
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (send.disabled) return;
    if (subj.value === 'security') { say('sec'); return; }
    var msgEl = document.getElementById('f-msg'), msg = msgEl.value.trim();
    if (!msg) { say('need'); msgEl.focus(); return; }
    var payload = { name: document.getElementById('f-name').value.trim(), email: document.getElementById('f-mail').value.trim(), subject: subj.value, message: msg, hp: document.getElementById('f-web').value };
    send.disabled = true; send.setAttribute('aria-disabled', 'true'); say('sending');
    var done = function (ok) {
      send.disabled = false; send.removeAttribute('aria-disabled');
      if (ok) { form.reset(); sync(); say('sent'); } else { say('err'); }
    };
    fetch(form.getAttribute('data-endpoint'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), credentials: 'omit', referrerPolicy: 'no-referrer' })
      .then(function (r) { done(r.ok); }, function () { done(false); });
  });
})();
