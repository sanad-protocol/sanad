---
key: contact
lang: en
path: /contact/
title: Contact
description: Project mailboxes and addresses of Sanad.
---

## Write to the project

This page sends nothing. The form only prepares a message: the text is passed to the Outlook page that you open (or to your own mail program), and you send it yourself from there. The site does not receive or store it. Replies may take several days.

<form class="mailform" id="mailform" action="mailto:contact@sanadprotocol.org" method="post" enctype="text/plain" data-to="contact@sanadprotocol.org" data-prefix="[Sanad] " data-sec="Security reports: please use the security page." data-blocked="The browser blocked the new tab. Allow pop-ups for this site or use another option." data-need="Please enter a message.">
<p><label for="f-name">Name (optional)</label><input id="f-name" name="name" type="text" autocomplete="name"></p>
<p><label for="f-mail">Your e-mail address for the reply (optional)</label><input id="f-mail" name="email" type="email" autocomplete="email"></p>
<p><label for="f-subj">Subject</label><select id="f-subj" name="subject"><option value="general">General</option><option value="specification">Specification comment</option><option value="implementation">Implementation</option><option value="press">Press</option><option value="security">Security</option></select></p>
<p id="f-secnote" class="formnote">Security reports are not handled by this form. See <a href="/security/">Security</a> and write to security@sanadprotocol.org.</p>
<p><label for="f-msg">Message</label><textarea id="f-msg" name="message" rows="8" required></textarea></p>
<p class="hp" aria-hidden="true"><label for="f-web">Leave this field empty</label><input id="f-web" name="website" type="text" tabindex="-1" autocomplete="off"></p>
<p class="formbtns"><button class="btn primary" type="submit" value="outlook">Write in Outlook</button> <button class="btn" type="submit" value="live">Outlook.com / personal account</button> <button class="btn" type="submit" value="mailto">Open in my mail program</button></p>
<p><span id="f-status" class="formnote" role="status"></span></p>
</form>

<p class="formnote">The buttons need JavaScript. Without it, use the plain address below.</p>
<p>If your mail program does not open, write to <a href="mailto:contact@sanadprotocol.org">contact@sanadprotocol.org</a> <button type="button" class="btn small" id="copyaddr" data-copied="Copied" data-label="Copy address" hidden>Copy address</button></p>

## Addresses

<dl class="defs">
<dt>General</dt><dd>contact@sanadprotocol.org</dd>
<dt>Security</dt><dd>security@sanadprotocol.org: see <a href="/security/">Security</a> and <a href="/.well-known/security.txt">security.txt</a></dd>
<dt>Press</dt><dd>press@sanadprotocol.org: see <a href="/for/press/">For press</a></dd>
<dt>Comments on the specification</dt><dd>Public issues in the project repository (to be published at <code>sanad-protocol/sanad</code>) or by e-mail.</dd>
<dt>Postal address</dt><dd>Dr. Arash Kermani Kolankeh, Flat 1108, The Pad by Omniyat, Dubai, United Arab Emirates</dd>
<dt>Response time</dt><dd>The project is run by one person for now; replies may take several days.</dd>
</dl>
