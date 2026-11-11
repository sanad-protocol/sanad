---
key: engine
lang: de
path: /de/engine/
nav: engine
title: Die Sanad-Engine
description: Die Sanad-Engine führt eine Prüfung von Anfang bis Ende durch und stellt Nachweise aus, die eine prüfende Stelle prüfen und nach eigener Richtlinie bewerten kann. Version 0.2.0.
toc: true
---

<!-- glance -->
- Ein kleines Programm, das eine Prüfung von der Vorlage bis zum versiegelten Nachweis durchführt, mit verdeckten Festlegungen, Transparenzprotokoll und Verifikation nach der Richtlinie der prüfenden Stelle.
- Setzt den Algorithmus `sanad-0.1` aus SANAD-SPEC-0.1 mit drei Abweichungen vom v0.1-Referenzcode um, die offene Entscheidungen sind (siehe unten). Paketversion 0.2.0. Keine Laufzeitabhängigkeiten; Node 22 oder neuer.
- Bestätigende behalten ihre eigenen Schlüssel. Experimentell: keine externe kryptografische Prüfung. Vertrauen beruht auf dem, was die prüfende Stelle festlegt (Pinning).
<!-- /glance -->

## Was die Engine ist

Die Engine führt eine Prüfung von Anfang bis Ende durch. Sie hält eine Prüfungsvorlage, lädt Bestätigende über ihre DID ein, nimmt verdeckte Festlegungen (Commits) und danach die Offenlegungen (Reveals) entgegen, baut die Belegkette, versiegelt mit der Kernbibliothek einen Nachweis, signiert ihn mit dem Schlüssel der ausstellenden Stelle und hängt Hashes an ein Transparenzprotokoll an. Danach kann jede Person den Nachweis prüfen: den Beleg der ausstellenden Stelle, den Bündel-Hash, die Signaturen der Bestätigenden und die Aufnahme im Protokoll, anschließend die Anerkennungsfunktion nach der Richtlinie der prüfenden Stelle. Die von der Vorlage empfohlene Richtlinie ist nur eine Empfehlung.

Die Engine gibt es als Bibliothek, als HTTP-Schnittstelle (`node:http`), als Kommandozeilenwerkzeug und als kleine Demonstrationsseite.

## Was sie nicht tut

- Sie prüft Bestätigende nicht auf Eignung. Das tut für das Protokoll niemand (Spezifikation, Abschnitt 9).
- Sie betreibt weder einen Live-Raum noch Video oder Aufsicht und nimmt keine Zahlungen an.
- Sie lädt keine DID-Dokumente über das Netz, veröffentlicht keine Fähigkeitenkarten und betreibt keinen Index.
- Sie setzt keine selektive Offenlegung (SD-JWT) und keine Bitstring Status List um und verankert Prüfpunkte nicht mit OpenTimestamps.
- Sie erstellt keine Ranglisten von Personen.
- Sie ist keine Akkreditierung und sagt nichts über die Redlichkeit einer Prüfung: Die Kette belegt, was beobachtet wurde.

## Verhältnis zur Spezifikation

Die Engine setzt den Algorithmus `sanad-0.1` aus [SANAD-SPEC-0.1](/spec/0.1/) mit Abweichungen vom v0.1-Referenzcode um. Die Spezifikation bleibt bei Version 0.1 und ihr Text wird nicht geändert; der Code hat Version 0.2.0. Die Regeln dieses Codes weichen in drei Punkten vom v0.1-Referenzcode ab: Eine zweite Bewertung derselben bestätigenden Person für denselben Beleg wird unter R1 verworfen (v0.1 zählte beide); mit der optionalen Signaturprüfung verwirft eine fehlgeschlagene Signatur die Bestätigung unter R1 (v0.1 prüfte keine Signaturen); und eine Richtlinie muss vollständig und im Wertebereich sein, die behauptete Stufe muss 0 bis 5 sein, sonst verweigert die Funktion die Auswertung (v0.1 rechnete mit allem, was sie bekam). Ohne doppelte Bewertungen, mit gültiger vollständiger Richtlinie und ohne Signaturprüfung sind die Ergebnisse gleich denen von v0.1, und die 20 Konformitätsvektoren liefern dieselben Ergebnisse; bei zufälligen Nachweisen mit doppelten Bewertungen weichen sie ab. Ob die geänderten Regeln eine neue Algorithmus-Kennung brauchen, ist eine offene Entscheidung (siehe Offene Punkte). Wo Spezifikationstext und Referenzcode voneinander abweichen, folgt die Engine dem Referenzcode und den 20 Konformitätsvektoren. Die Abweichungen stehen unter [Offene Punkte](#offene-punkte).

## Die Bestandteile

| Bestandteil | Aufgabe |
|---|---|
| `reference/` (`@sanad-protocol/core` 0.2.0) | Kanonisches JSON, SHA-256, Hilfen zum Versiegeln, Regeln R1 bis R8, die 20 Konformitätsvektoren und der Befehl `sanad` (`verify`, `run-vectors`). |
| `engine/` (`@sanad-protocol/engine` 0.2.0) | Einfache ES-Module; `dist/sanad-engine.mjs` ist eine einzelne Bündeldatei aus Kern und Engine zum Einbinden. |
| Schlüssel | Ed25519-Schlüssel, `did:key`, abgetrennte JWS, DID-Dokumentverläufe mit Schlüsselwechsel und Widerruf. |
| Vorlagen | Schema und Validierung der Vorlagen; der Vorlagen-Hash wird festgehalten. |
| Festlegung und Offenlegung | Verdeckte Festlegungen, Offenlegungen, Fristen, verspätete und fehlende Offenlegungen, Unabhängigkeitsprüfungen. |
| Belegkette und Nachweis | Versiegeln, Bündel-Hash, Beleg der ausstellenden Stelle, Prüfung des Nachweises. |
| Transparenzprotokoll | Merkle-Baum (RFC 9162) mit Inklusions- und Konsistenzbeweisen und signierten Prüfpunkten. |
| Statistik der Bestätigenden | Prüfungen und Übereinstimmung, abgeleitet aus abgeschlossenen Prüfungen. |
| Speicher | Adapter für Arbeitsspeicher, Dateien (JSON-Dateien und JSON-Zeilen) und SQLite. |
| HTTP-Schnittstelle und Demonstrationsseite | JSON über `node:http`; strenge Content-Security-Policy, kein externer Code. |
| Kommandozeile | `sanad-engine`. |
| Beispiele | Drei Vorlagen mit Skriptläufen in `engine/examples/`. |
| Engine-Vektoren | Deterministische Vektoren in `engine/vectors/`. |

## Schnellstart

```
git clone https://github.com/sanad-protocol/sanad.git
cd sanad
npm ci
node engine/bin/sanad-engine init
node engine/bin/sanad-engine serve
```

`init` schreibt den Schlüssel der ausstellenden Stelle und den Protokollschlüssel in Dateien mit Modus 0600 und legt das Datenverzeichnis an. `serve` startet die HTTP-Schnittstelle und die Demonstrationsseite.

## Ein Beispiel als Skript

```
node engine/examples/run-all.mjs
```

Das Skript führt drei Beispielprüfungen von der Vorlage bis zum geprüften Nachweis durch: eine mündliche Mathematikprüfung, eine praktische Handwerksprüfung und eine mündliche Sprachprüfung. Es nutzt ein getrenntes Demonstrationshilfsmittel, das Schlüssel für Bestätigende erzeugt, damit ein einziges Skript mehrere Bestätigende spielen kann.

## Kommandozeile

| Befehl | Zweck |
|---|---|
| `sanad-engine init [--dir]` | Schlüssel und Datenverzeichnis anlegen. |
| `sanad-engine keygen --out <Datei>` | Demonstrationsschlüssel für Bestätigende erzeugen. |
| `sanad-engine template add <Datei>` | Vorlage registrieren. |
| `sanad-engine create-assessment --template <id> --subject <id> --level <n>` | Prüfung anlegen; Optionen `--evidence <Datei>`, `--commit-by`, `--reveal-by`. |
| `sanad-engine invite <assessment> --attestor <did> --evidence <id>` | Bestätigende einladen; Option `--role`. |
| `sanad-engine commit <assessment> <attestationId> --key <Datei> --level <n>` | Verdeckte Festlegung; der Nonce wird in einer lokalen Datei neben dem Schlüssel gespeichert. |
| `sanad-engine reveal <assessment> <attestationId> --key <Datei>` | Offenlegung. |
| `sanad-engine finalize <assessment> [--out]` | Nachweis versiegeln und ausstellen. |
| `sanad-engine verify <credential.json> [--policy <Datei>]` | Nachweis prüfen. |
| `sanad-engine log checkpoint`, `inclusion`, `consistency` | Transparenzprotokoll lesen. |
| `sanad-engine serve [--port] [--host]` | HTTP-Server starten. |

Der Kernbefehl `sanad` bietet `verify` (nur Anerkennung, ohne Signaturprüfung, und er sagt das) und `run-vectors [Datei]`.

## HTTP-Schnittstelle

JSON über `node:http`; die Größe des Anfragekörpers ist auf 256 KiB begrenzt, bei POST ist `content-type: application/json` erforderlich. Routen für den Betrieb brauchen `authorization: Bearer <Betriebstoken>`. Routen für Bestätigende sind offen, weil der Anfragekörper signiert ist. Fehler haben die Form `{ "error": code, "message": text }`.

| Methode und Pfad | Wer | Zweck |
|---|---|---|
| `GET /healthz` | alle | Lebenszeichen. |
| `GET /v1/info` | alle | Engine-Version, Algorithmus, DID der ausstellenden Stelle, Protokollkennung. |
| `POST /v1/templates`, `GET /v1/templates`, `GET /v1/templates/:id` | Betrieb, alle | Vorlagen registrieren und lesen. |
| `POST /v1/dids`, `GET /v1/dids/:did` | Betrieb, alle | DID-Dokumentverlauf oder signierte Aktualisierung registrieren. |
| `POST /v1/assessments`, `GET /v1/assessments/:id` | Betrieb, alle | Anlegen; öffentliche Ansicht (vor der Offenlegung ohne Nonces). |
| `POST /v1/assessments/:id/invite` | Betrieb | Bestätigende einladen. |
| `POST /v1/assessments/:id/commit` | Bestätigende (signiert) | Verdeckte Festlegung. |
| `POST /v1/assessments/:id/reveal` | Bestätigende (signiert) | Offenlegung. |
| `POST /v1/assessments/:id/finalize` | Betrieb | Nachweis versiegeln und ausstellen. |
| `GET /v1/credentials/:id` | alle | Der Nachweis. |
| `POST /v1/verify` | alle | Prüfbericht zu einem übermittelten Nachweis und einer optionalen Richtlinie. |
| `GET /v1/log/checkpoint`, `/v1/log/entries`, `/v1/log/inclusion`, `/v1/log/consistency` | alle | Das Transparenzprotokoll. |
| `GET /v1/attestors/:did/stats` | alle | Abgeleitete Statistik. |
| `GET /` | alle | Die Demonstrationsseite. |

## Schlüssel

Durchgehend Ed25519 (RFC 8032, `node:crypto`). Bestätigende halten ihre privaten Schlüssel selbst. Die Engine, ihr HTTP-Server und ihr Bibliothekseinstieg erhalten, speichern oder erzeugen nie einen privaten Schlüssel von Bestätigenden; sie erhalten nur signierte Aussagen. Der Schlüssel der ausstellenden Stelle und der Protokollschlüssel gehören dem Betrieb, der die Engine laufen lässt. Das Demonstrationshilfsmittel, das Schlüssel für Bestätigende erzeugt, ist eine eigene Datei und wird weder vom Kern noch vom HTTP-Server noch vom Bibliothekseinstieg eingebunden.

Ein `did:key` kann nicht gewechselt werden; ein verlorener oder kompromittierter `did:key` wird durch eine neue Identität ersetzt. Andere DIDs werden bei der Engine als Dokumentverlauf registriert; jede spätere Version muss von einem Schlüssel signiert sein, der in der vorigen Version gültig war.

## Sicherheitshinweise

- Jede signierte Nutzlast nennt die Prüfung, die Bestätigungskennung und ihren Signaturtyp, und eine Festlegung wird nur einmal angenommen; eine Aussage lässt sich also nicht für einen anderen Zweck wiederverwenden.
- Die Mitgliedermengen sind geschlossen, das JSON ist kanonisch und der Bündel-Hash deckt vollständige Objekte ab; ein versiegeltes Bündel lässt sich also nicht ändern, ohne den Hash zu ändern.
- Geheimnisse wie das Betriebstoken werden in konstanter Zeit verglichen. Festlegungen sind öffentliche Werte.
- Rückdatierung mit einem gestohlenen Schlüssel wird nicht erkannt: Ein widerrufener oder gestohlener Schlüssel kann weiterhin Aussagen mit früherem Datum signieren, und die prüfende Stelle prüft den Schlüssel gegen das Datum, das die Aussage selbst trägt. Die Zeitstempel des Protokolls stammen vom Betreiber und schließen diese Lücke nicht.
- Absprachen, Hilfe außerhalb des Kamerabildes und Identitätsprüfungen kann keine Software beweisen.

## Was nicht behauptet wird

- Die Engine ist experimentell und wurde nicht extern kryptografisch geprüft.
- Zwei unabhängige Prüfprogramme, aus den Dokumenten geschrieben (Python und Ruby, in `engine/test/crosscheck/`), stimmen auf den Beispielnachweisen mit ihr überein. Das zeigt, dass die Formate reproduzierbar sind; es ist keine Prüfung.
- Statistiken der Bestätigenden (Sitzungen, Übereinstimmung) liefert die ausstellende Stelle; sie lassen sich aus dem Protokoll, das nur Hashwerte enthält, nicht nachrechnen.
- Eine `did:web`-Identität wird vom Betreiber behauptet: Nichts belegt, dass der Registrierende die Domain kontrolliert, und eine im Nachweis mitgelieferte Schlüsselhistorie ist nur die Behauptung der ausstellenden Stelle. Die prüfende Stelle muss die Schlüssel festlegen (Pinning).
- Dass jede Festlegung vor jeder Offenlegung kam, bestätigt der Betreiber; der Nachweis enthält die signierten Festlegungen nicht.
- Eine Prüfung ist nur so vertrauenswürdig wie das, was die prüfende Stelle festlegt: Ein nicht festgelegter Aussteller oder Protokollschlüssel oder eine eingebettete Historie lässt den Bericht scheitern.
- Der HTTP-Server hat keine Ratenbegrenzung; der Prüfaufwand ist durch feste Obergrenzen für die Größe eines Dokuments beschränkt.
- Betroffene müssen UUID- oder Hash-URNs sein; das ist eine Schutzplanke und kein Beweis, dass nichts Persönliches enthalten ist; Freitext in Belegen ist öffentlich.
- Die Primitive Ed25519 und SHA-256 stammen von Node.
- Es gibt noch keine Bestätigenden außerhalb des Umfelds der verantwortlichen Person.
- Sie ist keine Blockchain, hat kein Token und ist keine Akkreditierung.

## Anbindung an ein System

Eine Plattform behält ihre eigenen Abläufe und lässt genau ein Modul mit der Engine sprechen. Es gibt drei Wege: die Einzeldatei-Bibliothek in der Plattform, einen HTTP-Dienst an der Seite oder nur die Prüfung. Die Anleitung [Plug Sanad into any system](https://github.com/sanad-protocol/sanad/blob/main/docs/TUTORIAL-plug-sanad-into-any-system.md) (englisch) führt durch alle drei, mit Port-und-Adapter-Muster, Signaturticket für Bestätigende im Browser, Abbildung von Stufen, Fristen, dem, was eine Plattform aufbewahren muss (Schlüsselsicherungen und Prüfpunkte des Protokolls), dem, was sie nicht tun darf, Fehlerfällen und einer Checkliste, ob eine Anbindung dem Protokoll treu ist. Was noch nicht getestet ist, ist im Text gekennzeichnet.

## Offene Punkte

Das Designdokument der Engine nennt zehn Stellen (Punkte 1 bis 10 seines Abschnitts 14), an denen Spezifikationstext und Referenzcode voneinander abweichen oder eine Frage offen lassen, und spätere Punkte (11 bis 40), die Entscheidungen der Engine und die drei Regeländerungen festhalten. Eine eigene Liste, [Spec decisions needed before v1.0](https://github.com/sanad-protocol/sanad/blob/main/docs/SPEC-DECISIONS-NEEDED.md) (englisch), enthält 25 Entscheidungen mit Optionen und je einer Empfehlung, darunter die signierten Festlegungen im Nachweis, was die Signatur der Bestätigenden abdeckt, nachprüfbare Statistiken, die Kettenregel, die Monatslänge (eine harte Schwelle, keine Rundung) und eine mögliche `sanad-0.2`. Die Spezifikation wird nicht geändert; die Engine folgt dem Referenzcode und den Vektoren. Die ersten zehn, kurz gefasst: die Form des Commit-Hashs; Feldnamen in Bestätigungen und Belegen; was der Beleg-Hash abdeckt; die Länge eines Monats; was die Signatur der Bestätigenden abdeckt; den Umgang mit einer fehlgeschlagenen Signatur unter R1; die Definition des Bündel-Hashs; welchen Median die Übereinstimmungsstatistik verwendet; wie ein Nachweis gesichert wird; und welche Ereignisse protokolliert werden. Die vollständige Liste (englisch) steht im [Designdokument](https://github.com/sanad-protocol/sanad/blob/main/engine/DESIGN.md).

## Konformitätserklärung

Die Sanad-Engine 0.2.0 setzt die Konformitätsklassen Verifier, Issuer, Attestor (Hilfsprogramm für Clients) und Log von SANAD-SPEC-0.1 um, soweit die öffentlichen Vektoren sie prüfen: Sie besteht die 20 Konformitätsvektoren der Spezifikation und die Engine-Vektoren in `engine/vectors/`. Einschränkungen: Die 20 Konformitätsvektoren werden zur Laufzeit versiegelt und legen keine Hashwerte fest, sie prüfen also Verhalten und keine Übereinstimmung auf Byte-Ebene; die Engine-Vektoren legen Bündel-Hashes fest, stammen aber aus dieser Implementierung; die Engine weicht in den drei oben genannten Regeln vom v0.1-Referenzcode ab, und die Entscheidungen in `docs/SPEC-DECISIONS-NEEDED.md` sind offen; die Engine ist experimentell und nicht kryptografisch geprüft. Diese Erklärung stammt von der verantwortlichen Person; sie wurde von keiner unabhängigen Stelle geprüft.

Siehe auch [Konformität](/conformance/) und [Für Implementierende](/for/implementers/).
