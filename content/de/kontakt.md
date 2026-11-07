---
key: contact
lang: de
path: /de/kontakt/
title: Kontakt
description: So erreichen Sie das Sanad-Projekt.
---

## Schreiben Sie dem Projekt

Diese Seite sendet nichts. Das Formular bereitet nur eine Nachricht vor: Der Text wird an die Outlook-Seite übergeben, die Sie öffnen (oder an Ihr eigenes Mailprogramm), und Sie senden ihn dort selbst ab. Die Seite empfängt und speichert ihn nicht. Antworten können einige Tage dauern.

<form class="mailform" id="mailform" action="mailto:contact@sanadprotocol.org" method="post" enctype="text/plain" data-to="contact@sanadprotocol.org" data-prefix="[Sanad] " data-sec="Sicherheitsmeldungen: bitte die Sicherheitsseite verwenden." data-blocked="Der Browser hat den neuen Tab blockiert. Erlauben Sie Pop-ups für diese Seite oder nutzen Sie eine andere Möglichkeit." data-need="Bitte geben Sie eine Nachricht ein.">
<p><label for="f-name">Name (optional)</label><input id="f-name" name="name" type="text" autocomplete="name"></p>
<p><label for="f-mail">Ihre E-Mail-Adresse für die Antwort (optional)</label><input id="f-mail" name="email" type="email" autocomplete="email"></p>
<p><label for="f-subj">Betreff</label><select id="f-subj" name="subject"><option value="general">Allgemein</option><option value="specification">Anmerkung zur Spezifikation</option><option value="implementation">Implementierung</option><option value="press">Presse</option><option value="security">Sicherheit</option></select></p>
<p id="f-secnote" class="formnote">Sicherheitsmeldungen bearbeitet dieses Formular nicht. Siehe <a href="/security/" hreflang="en">Security</a> und schreiben Sie an security@sanadprotocol.org.</p>
<p><label for="f-msg">Nachricht</label><textarea id="f-msg" name="message" rows="8" required></textarea></p>
<p class="hp" aria-hidden="true"><label for="f-web">Dieses Feld leer lassen</label><input id="f-web" name="website" type="text" tabindex="-1" autocomplete="off"></p>
<p class="formbtns"><button class="btn primary" type="submit" value="outlook">In Outlook schreiben</button> <button class="btn" type="submit" value="live">Outlook.com / privates Konto</button> <button class="btn" type="submit" value="mailto">In meinem Mailprogramm öffnen</button></p>
<p><span id="f-status" class="formnote" role="status"></span></p>
</form>

<p class="formnote">Die Schaltflächen benötigen JavaScript. Ohne JavaScript verwenden Sie die Adresse unten.</p>
<p>Falls sich Ihr Mailprogramm nicht öffnet, schreiben Sie an <a href="mailto:contact@sanadprotocol.org">contact@sanadprotocol.org</a> <button type="button" class="btn small" id="copyaddr" data-copied="Kopiert" data-label="Adresse kopieren" hidden>Adresse kopieren</button></p>

## Adressen

<dl class="defs">
<dt>Allgemein</dt><dd>contact@sanadprotocol.org</dd>
<dt>Sicherheit</dt><dd>security@sanadprotocol.org (siehe <a href="/security/" hreflang="en">Security</a>)</dd>
<dt>Presse</dt><dd>press@sanadprotocol.org</dd>
<dt>Anmerkungen zur Spezifikation</dt><dd>Öffentliche Beiträge im Projekt-Repository (vorgesehen unter <code>sanad-protocol/sanad</code>) oder per E-Mail.</dd>
<dt>Postanschrift</dt><dd>Dr. Arash Kermani Kolankeh, Flat 1108, The Pad by Omniyat, Dubai, Vereinigte Arabische Emirate</dd>
<dt>Antwortzeit</dt><dd>Das Projekt wird vorerst von einer Person betrieben; Antworten können einige Tage dauern.</dd>
</dl>
