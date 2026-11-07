---
key: home
lang: de
path: /de/
template: home
title: Sanad: ein offenes Protokoll zur nachrechenbaren Anerkennung von Fähigkeiten
h1: Sanad: ein offenes Protokoll zur nachrechenbaren Anerkennung von Fähigkeiten
description: Sanad ist ein Protokoll im Entwurfsstadium. Eine Qualifikation ist eine Kette aus Behauptung, Nachweisen und signierten Bestätigungen, die jede Stelle nach eigener Richtlinie nachrechnen kann. Kein Token, keine Akkreditierung.
lead: Sanad legt ein Datenmodell für Behauptungen, Nachweise und Bestätigungen fest, eine deterministische Anerkennungsfunktion, die eine prüfende Stelle nach ihrer eigenen Richtlinie ausführt, und eine Konformitätsprüfung mit Referenzimplementierung.
---

<ul class="cta">
<li><a class="primary" href="/spec/0.1/">Spezifikation lesen (englisch)</a></li>
<li><a href="/explainer/">Erklärseite ansehen</a></li>
<li><a href="/de/mitmachen/">Mitmachen</a></li>
</ul>

<!-- glance -->
- **Was:** ein Datenmodell und eine deterministische Anerkennungsfunktion für Fähigkeiten, die zu jedem Ergebnis eine öffentliche Begründung liefert.
- **Wer entscheidet:** die prüfende Stelle. Jedes Unternehmen, jede Schule und jede Hochschule wendet auf dieselben Nachweise ihre eigene veröffentlichte Richtlinie an.
- **Was Sanad nicht ist:** keine Währung, keine Rangliste von Personen, keine Akkreditierung.
- **Stand:** Entwurf 0.1 zur Diskussion; vorerst von einer Person betreut. Siehe [Status und Grenzen](/de/status/).
<!-- /glance -->

## Das Problem

Viele Menschen können etwas, das sie nicht belegen können. Zeugnisse gehen verloren, Einrichtungen schließen, Staaten erkennen Studienleistungen nicht mehr an, und ein Zertifikat sagt wenig darüber, wie es zustande kam. Unternehmen und Hochschulen können kaum prüfen, was hinter einer Behauptung steht, und verlassen sich daher auf Marken und Grenzen statt auf Nachweise.

## So funktioniert es

<ol class="steps wide">
<li><strong>Behauptung</strong>Eine Person erklärt eine Fähigkeit auf einem Niveau, zum Beispiel Lineare Algebra auf Niveau 4. Die Fähigkeit ist ein Knoten in einem offenen, versionierten Begriffsgraphen.</li>
<li><strong>Nachweis</strong>Die Behauptung stützt sich auf Nachweise verschiedener Art: wiederholbare Übungsläufe, eine von Prüfenden beobachtete Sitzung, begutachtete Arbeiten, gegenseitige Begutachtung.</li>
<li><strong>Bestätigung</strong>Unabhängige Bestätigende signieren, was sie gesehen haben. Bewertungen werden zuvor verdeckt festgelegt und erst danach offengelegt, sodass sie unabhängig bleiben.</li>
<li><strong>Anerkennung</strong>Jede Stelle führt die veröffentlichte Funktion mit ihrer eigenen Richtlinie aus und erhält ein Niveau, eine Verlässlichkeit und eine schrittweise Begründung.</li>
</ol>

## Für wen

<div class="cards wide">
<div><h3>Lernende ohne übertragbare Nachweise</h3><p>Menschen, deren Studium oder Arbeit dort, wo sie sind, nicht anerkannt wird, können überprüfbare Nachweise mitführen, die nicht von einer einzelnen Einrichtung abhängen.</p></div>
<div><h3>Prüfende und Bestätigende</h3><p>Jede und jeder darf bestätigen. Die Zahl der Sitzungen und die Übereinstimmung mit anderen Prüfenden sind öffentlich und nachrechenbar.</p></div>
<div><h3>Hochschulen und Unternehmen</h3><p>Prüfende Stellen wählen ihre Richtlinie, zum Beispiel drei Bestätigende und eine Präsenzsitzung, und können genau darlegen, wie ein Ergebnis zustande kam.</p></div>
<div><h3>Entwickelnde</h3><p>Spezifikation, Konformitätsvektoren und Referenzcode sind offen. Unabhängige Implementierungen machen aus einem Entwurf einen Standard.</p></div>
</div>

<div class="status-box">

### Status

Sanad ist ein **Entwurf (Version 0.1)** zur Diskussion. Er wurde weder von einer Normungsorganisation noch von juristischer oder kryptografischer Seite unabhängig geprüft. Sanad beruht auf **dezentraler Bewertung**: Es akkreditiert niemanden und bestimmt nicht, was eine prüfende Stelle akzeptieren muss. Es gibt **kein Token** und keine finanzielle Komponente. Bis die Open Sanad Foundation (VAE) besteht, handelt der Autor, Dr. Arash Kermani Kolankeh, als kommissarischer Verantwortlicher; eine zweite verantwortliche Person wird gewonnen; die [Governance-Charta](/governance/) begrenzt, was eine einzelne Person tun darf.

</div>

## Einstieg

- Lesen Sie die [Spezifikation](/spec/0.1/) (englisch, etwa 20 Minuten).
- Öffnen Sie die [Erklärseite](/explainer/), um eine Richtlinie zu ändern und die Begründung neu berechnen zu lassen.
- Lesen Sie die [Fragen und Antworten](/faq/) und erfahren Sie, wie Sie [mitmachen](/de/mitmachen/) können.
