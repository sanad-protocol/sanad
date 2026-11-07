---
key: contact
lang: de
path: /de/kontakt/
title: Kontakt
description: So erreichen Sie das Sanad-Projekt.
---

## Schreiben Sie dem Projekt

Nachrichten werden an das Projekt gesendet und auf dessen Server gespeichert, um sie zu beantworten. Siehe die <a href="/de/datenschutz/">Datenschutzerklärung</a>. Antworten können einige Tage dauern.

<form class="mailform" id="mailform" method="post" novalidate data-endpoint="https://rtc.kamangir.school/api/v1/contact" data-sending="Wird gesendet …" data-sent="Danke. Ihre Nachricht wurde gesendet." data-err="Die Nachricht konnte nicht gesendet werden. Ihr Text bleibt oben erhalten. Bitte schreiben Sie stattdessen an contact@sanadprotocol.org." data-need="Bitte geben Sie eine Nachricht ein." data-sec="Sicherheitsmeldungen: bitte die Sicherheitsseite verwenden.">
<p><label for="f-name">Name (optional)</label><input id="f-name" name="name" type="text" autocomplete="name"></p>
<p><label for="f-mail">Ihre E-Mail-Adresse für die Antwort (optional)</label><input id="f-mail" name="email" type="email" autocomplete="email"></p>
<p><label for="f-subj">Betreff</label><select id="f-subj" name="subject"><option value="general">Allgemein</option><option value="specification">Anmerkung zur Spezifikation</option><option value="implementation">Implementierung</option><option value="press">Presse</option><option value="security">Sicherheit</option></select></p>
<p id="f-secnote" class="formnote">Sicherheitsmeldungen bearbeitet dieses Formular nicht. Siehe <a href="/security/" hreflang="en">Security</a> und schreiben Sie an security@sanadprotocol.org.</p>
<p><label for="f-msg">Nachricht</label><textarea id="f-msg" name="message" rows="8" required></textarea></p>
<p class="hp" aria-hidden="true"><label for="f-web">Dieses Feld leer lassen</label><input id="f-web" name="website" type="text" tabindex="-1" autocomplete="off"></p>
<p><button class="btn primary" type="submit" id="f-send">Senden</button></p>
<p id="f-status" class="formnote" role="status" aria-live="polite"></p>
<noscript><p class="formnote">Zum Senden wird JavaScript benötigt. Ohne JavaScript schreiben Sie an die Adresse unten.</p></noscript>
</form>

<p class="formnote">Reine Adresse, falls das Senden nicht funktioniert: <a href="mailto:contact@sanadprotocol.org">contact@sanadprotocol.org</a></p>

## Adressen

<dl class="defs">
<dt>Allgemein</dt><dd>contact@sanadprotocol.org</dd>
<dt>Sicherheit</dt><dd>security@sanadprotocol.org (siehe <a href="/security/" hreflang="en">Security</a>)</dd>
<dt>Presse</dt><dd>press@sanadprotocol.org</dd>
<dt>Anmerkungen zur Spezifikation</dt><dd>Öffentliche Beiträge im Projekt-Repository (vorgesehen unter <code>sanad-protocol/sanad</code>) oder per E-Mail.</dd>
<dt>Postanschrift</dt><dd>Dr. Arash Kermani Kolankeh, Flat 1108, The Pad by Omniyat, Dubai, Vereinigte Arabische Emirate</dd>
<dt>Antwortzeit</dt><dd>Das Projekt wird vorerst von einer Person betrieben; Antworten können einige Tage dauern.</dd>
</dl>
