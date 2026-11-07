// Progressive enhancement only: copy buttons on code blocks and the contact form. The pages are fully readable without this file.
(function () {
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
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (document.getElementById('f-web').value) return;
    if (subj.value === 'security') { status.textContent = form.getAttribute('data-sec'); return; }
    var msg = document.getElementById('f-msg').value.trim();
    if (!msg) { status.textContent = form.getAttribute('data-need'); document.getElementById('f-msg').focus(); return; }
    var name = document.getElementById('f-name').value.trim(), mail = document.getElementById('f-mail').value.trim();
    var body = msg + (name || mail ? '\r\n\r\n--\r\n' + (name ? name + '\r\n' : '') + (mail ? mail + '\r\n' : '') : '');
    var subject = form.getAttribute('data-prefix') + label(subj), to = form.getAttribute('data-to');
    var q = 'to=' + encodeURIComponent(to) + '&subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
    var how = e.submitter && e.submitter.value ? e.submitter.value : 'outlook';
    status.textContent = '';
    if (how === 'mailto') { window.location.href = 'mailto:' + to + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body); return; }
    var base = how === 'live' ? 'https://outlook.live.com/mail/0/deeplink/compose?' : 'https://outlook.office.com/mail/deeplink/compose?';
    var w = window.open(base + q, '_blank', 'noopener,noreferrer'); if (!w) status.textContent = form.getAttribute('data-blocked');
  });
  var cb = document.getElementById('copyaddr');
  if (cb && canCopy) { cb.hidden = false; cb.addEventListener('click', function () { navigator.clipboard.writeText(form.getAttribute('data-to')).then(function () { cb.textContent = cb.getAttribute('data-copied'); setTimeout(function () { cb.textContent = cb.getAttribute('data-label'); }, 1800); }); }); }
})();
