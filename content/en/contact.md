---
key: contact
lang: en
path: /contact/
title: Contact
description: Project mailboxes and addresses of Sanad.
---

## Write to the project

Messages are sent to the project and stored on its server to answer them. See the <a href="/privacy/">privacy statement</a>. Replies may take several days.

<form class="mailform" id="mailform" method="post" novalidate data-endpoint="https://rtc.kamangir.school/api/v1/contact" data-sending="Sending…" data-sent="Thank you. Your message has been sent." data-err="The message could not be sent. Your text is kept above. Please write to info@sanadprotocol.org instead." data-need="Please enter a message." data-sec="Security reports: please use the security page.">
<p><label for="f-name">Name (optional)</label><input id="f-name" name="name" type="text" autocomplete="name"></p>
<p><label for="f-mail">Your e-mail address for the reply (optional)</label><input id="f-mail" name="email" type="email" autocomplete="email"></p>
<p><label for="f-subj">Subject</label><select id="f-subj" name="subject"><option value="general">General</option><option value="specification">Specification comment</option><option value="implementation">Implementation</option><option value="press">Press</option><option value="security">Security</option></select></p>
<p id="f-secnote" class="formnote">Security reports are not handled by this form. See <a href="/security/">Security</a> and write to info@sanadprotocol.org.</p>
<p><label for="f-msg">Message</label><textarea id="f-msg" name="message" rows="8" required></textarea></p>
<p class="hp" aria-hidden="true"><label for="f-web">Leave this field empty</label><input id="f-web" name="website" type="text" tabindex="-1" autocomplete="off"></p>
<p><button class="btn primary" type="submit" id="f-send">Send</button></p>
<p id="f-status" class="formnote" role="status" aria-live="polite"></p>
<noscript><p class="formnote">Sending needs JavaScript. Without it, write to the address below.</p></noscript>
</form>

<p class="formnote">Plain address, if sending does not work: <a href="mailto:info@sanadprotocol.org">info@sanadprotocol.org</a></p>

## Addresses

<dl class="defs">
<dt>Email</dt><dd>info@sanadprotocol.org</dd>
<dt>Security reports</dt><dd>Write to the same address with "Sanad security" in the subject: see <a href="/security/">Security</a> and <a href="/.well-known/security.txt">security.txt</a></dd>
<dt>Press</dt><dd>Same address: see <a href="/for/press/">For press</a></dd>
<dt>Comments on the specification</dt><dd>Public issues in the project repository (to be published at <code>sanad-protocol/sanad</code>) or by e-mail.</dd>
<dt>Postal address</dt><dd>Dr. Arash Kermani Kolankeh, Flat 1108, The Pad by Omniyat, Dubai, United Arab Emirates</dd>
<dt>Response time</dt><dd>The project is run by one person for now; replies may take several days.</dd>
</dl>
